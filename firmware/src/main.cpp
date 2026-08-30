#include <Arduino.h>
#include <Preferences.h>
#include <memory>

#include "usb_msc.h"

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>

namespace {
constexpr int kBootButton = 0;
constexpr size_t kPrivateKeySize = 32;
constexpr size_t kPublicKeySize = 65;
constexpr size_t kSaltSize = 16;
constexpr size_t kDerivedKeySize = 32;
constexpr uint32_t kConfirmationTimeoutMs = 15000;
constexpr char kHkdfInfo[] = "T-Dongle-S3 document key v1";

Preferences preferences;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context rng;
mbedtls_ecp_group group;
mbedtls_mpi privateKey;
mbedtls_ecp_point publicKey;
bool keyReady = false;

void sendError(const char *message) {
  Serial.print("ERR ");
  Serial.println(message);
}

int randomBytes(void *context, unsigned char *output, size_t length) {
  return mbedtls_ctr_drbg_random(context, output, length);
}

String encodeBase64(const uint8_t *data, size_t length) {
  size_t outputLength = 0;
  size_t capacity = 4 * ((length + 2) / 3) + 1;
  std::unique_ptr<uint8_t[]> output(new uint8_t[capacity]);
  if (mbedtls_base64_encode(output.get(), capacity, &outputLength, data, length) != 0) {
    return String();
  }
  output[outputLength] = '\0';
  return String(reinterpret_cast<char *>(output.get()));
}

bool decodeBase64(const String &input, uint8_t *output, size_t capacity, size_t &outputLength) {
  return mbedtls_base64_decode(
             output, capacity, &outputLength,
             reinterpret_cast<const uint8_t *>(input.c_str()), input.length()) == 0;
}

int hkdfSha256(const uint8_t *salt, size_t saltLength,
               const uint8_t *secret, size_t secretLength,
               uint8_t output[kDerivedKeySize]) {
  const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (sha256 == nullptr) {
    return -1;
  }
  uint8_t pseudorandomKey[32];
  int result = mbedtls_md_hmac(sha256, salt, saltLength, secret, secretLength,
                               pseudorandomKey);
  if (result != 0) {
    memset(pseudorandomKey, 0, sizeof(pseudorandomKey));
    return result;
  }
  uint8_t expandInput[sizeof(kHkdfInfo)];
  memcpy(expandInput, kHkdfInfo, sizeof(kHkdfInfo) - 1);
  expandInput[sizeof(kHkdfInfo) - 1] = 1;
  result = mbedtls_md_hmac(sha256, pseudorandomKey, sizeof(pseudorandomKey),
                           expandInput, sizeof(expandInput), output);
  memset(pseudorandomKey, 0, sizeof(pseudorandomKey));
  memset(expandInput, 0, sizeof(expandInput));
  return result;
}

bool savePrivateKey() {
  uint8_t bytes[kPrivateKeySize];
  if (mbedtls_mpi_write_binary(&privateKey, bytes, sizeof(bytes)) != 0) {
    return false;
  }
  preferences.begin("tdkey", false);
  size_t written = preferences.putBytes("private", bytes, sizeof(bytes));
  preferences.end();
  memset(bytes, 0, sizeof(bytes));
  return written == kPrivateKeySize;
}

bool loadOrCreateKey() {
  uint8_t stored[kPrivateKeySize];
  preferences.begin("tdkey", true);
  size_t length = preferences.getBytesLength("private");
  if (length == kPrivateKeySize) {
    preferences.getBytes("private", stored, sizeof(stored));
  }
  preferences.end();

  int result;
  if (length == kPrivateKeySize) {
    result = mbedtls_mpi_read_binary(&privateKey, stored, sizeof(stored));
    memset(stored, 0, sizeof(stored));
    if (result != 0 || mbedtls_ecp_check_privkey(&group, &privateKey) != 0) {
      return false;
    }
  } else {
    result = mbedtls_ecp_gen_privkey(&group, &privateKey, randomBytes, &rng);
    if (result != 0 || !savePrivateKey()) {
      return false;
    }
  }

  return mbedtls_ecp_mul(&group, &publicKey, &privateKey, &group.G,
                         randomBytes, &rng) == 0;
}

bool waitForConfirmation() {
#ifdef DISABLE_CONFIRMATION
  // Unattended mode: skip physical confirmation entirely
  return true;
#else
  Serial.println("CONFIRM press-BOOT");
  uint32_t started = millis();
  bool sawRelease = digitalRead(kBootButton) == HIGH;
  while (millis() - started < kConfirmationTimeoutMs) {
    bool pressed = digitalRead(kBootButton) == LOW;
    if (!pressed) {
      sawRelease = true;
    } else if (sawRelease) {
      delay(30);
      if (digitalRead(kBootButton) == LOW) {
        while (digitalRead(kBootButton) == LOW) {
          delay(10);
        }
        return true;
      }
    }
    delay(10);
  }
  return false;
#endif
}

void sendPublicKey() {
  uint8_t encoded[kPublicKeySize];
  size_t encodedLength = 0;
  int result = mbedtls_ecp_point_write_binary(
      &group, &publicKey, MBEDTLS_ECP_PF_UNCOMPRESSED,
      &encodedLength, encoded, sizeof(encoded));
  if (result != 0 || encodedLength != sizeof(encoded)) {
    sendError("public-key-export");
    return;
  }
  Serial.print("PUB ");
  Serial.println(encodeBase64(encoded, encodedLength));
}

void deriveForPeer(const String &peerText, const String &saltText) {
  uint8_t peerBytes[kPublicKeySize];
  uint8_t salt[kSaltSize];
  size_t peerLength = 0;
  size_t saltLength = 0;
  if (!decodeBase64(peerText, peerBytes, sizeof(peerBytes), peerLength) ||
      peerLength != sizeof(peerBytes) ||
      !decodeBase64(saltText, salt, sizeof(salt), saltLength) ||
      saltLength != sizeof(salt)) {
    sendError("bad-arguments");
    return;
  }

  mbedtls_ecp_point peer;
  mbedtls_mpi shared;
  mbedtls_ecp_point_init(&peer);
  mbedtls_mpi_init(&shared);
  int result = mbedtls_ecp_point_read_binary(&group, &peer, peerBytes, peerLength);
  if (result == 0) {
    result = mbedtls_ecp_check_pubkey(&group, &peer);
  }
  if (result != 0) {
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&shared);
    sendError("invalid-peer-key");
    return;
  }

  if (!waitForConfirmation()) {
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&shared);
    sendError("confirmation-timeout");
    return;
  }

  result = mbedtls_ecdh_compute_shared(&group, &shared, &peer, &privateKey,
                                       randomBytes, &rng);
  uint8_t sharedBytes[kPrivateKeySize];
  uint8_t derived[kDerivedKeySize];
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&shared, sharedBytes, sizeof(sharedBytes));
  }
  if (result == 0) {
    result = hkdfSha256(salt, sizeof(salt), sharedBytes, sizeof(sharedBytes),
                        derived);
  }

  mbedtls_ecp_point_free(&peer);
  mbedtls_mpi_free(&shared);
  memset(sharedBytes, 0, sizeof(sharedBytes));
  if (result != 0) {
    memset(derived, 0, sizeof(derived));
    sendError("key-derivation");
    return;
  }
  Serial.print("KEY ");
  Serial.println(encodeBase64(derived, sizeof(derived)));
  memset(derived, 0, sizeof(derived));
}

void handleCommand(String line) {
  line.trim();
  if (line == "HELLO") {
    Serial.println(keyReady ? "READY TDKEY1" : "ERR key-unavailable");
    return;
  }
  if (!keyReady) {
    sendError("key-unavailable");
    return;
  }
  if (line == "PUBLIC") {
    sendPublicKey();
    return;
  }
  if (line.startsWith("DERIVE ")) {
    int separator = line.indexOf(' ', 7);
    if (separator < 0) {
      sendError("bad-arguments");
      return;
    }
    deriveForPeer(line.substring(7, separator), line.substring(separator + 1));
    return;
  }
  sendError("unknown-command");
}
}  // namespace

void setup() {
  pinMode(kBootButton, INPUT_PULLUP);
  Serial.begin(115200);
  const bool storageReady = usb_msc_begin();

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng);
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&privateKey);
  mbedtls_ecp_point_init(&publicKey);

  const char personalization[] = "tdongle-document-key";
  int result = mbedtls_ctr_drbg_seed(
      &rng, mbedtls_entropy_func, &entropy,
      reinterpret_cast<const uint8_t *>(personalization), strlen(personalization));
  if (result == 0) {
    result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
  }
  keyReady = result == 0 && loadOrCreateKey();
  Serial.println(keyReady ? "READY TDKEY1" : "ERR key-initialization");
  if (storageReady) {
    Serial.printf("STORAGE SD %llu\n", usb_msc_capacity_bytes());
  } else {
    Serial.println("STORAGE unavailable");
  }
}

void loop() {
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    handleCommand(line);
  }
  delay(2);
}
