#include "usb_msc.h"

#include <Arduino.h>
#include <USB.h>
#include <USBMSC.h>

#include "driver/sdmmc_host.h"
#include "esp_err.h"
#include "sdmmc_cmd.h"

// LILYGO T-Dongle S3 onboard TF-card wiring. Each pin and the bus frequency
// can be overridden with a PlatformIO build flag for another ESP32-S3 board.
#ifndef POO_SDMMC_CLK_PIN
#define POO_SDMMC_CLK_PIN 12
#endif
#ifndef POO_SDMMC_CMD_PIN
#define POO_SDMMC_CMD_PIN 16
#endif
#ifndef POO_SDMMC_D0_PIN
#define POO_SDMMC_D0_PIN 14
#endif
#ifndef POO_SDMMC_D1_PIN
#define POO_SDMMC_D1_PIN 17
#endif
#ifndef POO_SDMMC_D2_PIN
#define POO_SDMMC_D2_PIN 21
#endif
#ifndef POO_SDMMC_D3_PIN
#define POO_SDMMC_D3_PIN 18
#endif
#ifndef POO_SDMMC_FREQUENCY_KHZ
#define POO_SDMMC_FREQUENCY_KHZ SDMMC_FREQ_DEFAULT
#endif

namespace {
constexpr uint16_t kUsbSectorSize = 512;

USBMSC msc;
sdmmc_card_t card;
bool cardReady = false;
alignas(4) uint8_t sectorBuffer[kUsbSectorSize];

bool transferInBounds(uint32_t lba, uint32_t offset, uint32_t size) {
  if (!cardReady || offset >= kUsbSectorSize) {
    return false;
  }
  const uint64_t firstByte =
      static_cast<uint64_t>(lba) * kUsbSectorSize + offset;
  const uint64_t cardBytes =
      static_cast<uint64_t>(card.csd.capacity) * card.csd.sector_size;
  return firstByte <= cardBytes && size <= cardBytes - firstByte;
}

int32_t mscRead(uint32_t lba, uint32_t offset, void *buffer,
                uint32_t bufsize) {
  if (!transferInBounds(lba, offset, bufsize)) {
    return 0;
  }

  auto *output = static_cast<uint8_t *>(buffer);
  uint64_t position = static_cast<uint64_t>(lba) * kUsbSectorSize + offset;
  uint32_t remaining = bufsize;
  while (remaining > 0) {
    const size_t sector = position / kUsbSectorSize;
    const size_t sectorOffset = position % kUsbSectorSize;
    const size_t chunk = min(static_cast<size_t>(remaining),
                             kUsbSectorSize - sectorOffset);
    if (sdmmc_read_sectors(&card, sectorBuffer, sector, 1) != ESP_OK) {
      return 0;
    }
    memcpy(output, sectorBuffer + sectorOffset, chunk);
    output += chunk;
    position += chunk;
    remaining -= chunk;
  }
  return bufsize;
}

int32_t mscWrite(uint32_t lba, uint32_t offset, uint8_t *buffer,
                 uint32_t bufsize) {
  if (!transferInBounds(lba, offset, bufsize)) {
    return 0;
  }

  const uint8_t *input = buffer;
  uint64_t position = static_cast<uint64_t>(lba) * kUsbSectorSize + offset;
  uint32_t remaining = bufsize;
  while (remaining > 0) {
    const size_t sector = position / kUsbSectorSize;
    const size_t sectorOffset = position % kUsbSectorSize;
    const size_t chunk = min(static_cast<size_t>(remaining),
                             kUsbSectorSize - sectorOffset);

    if (sectorOffset != 0 || chunk != kUsbSectorSize) {
      if (sdmmc_read_sectors(&card, sectorBuffer, sector, 1) != ESP_OK) {
        return 0;
      }
    }
    memcpy(sectorBuffer + sectorOffset, input, chunk);
    if (sdmmc_write_sectors(&card, sectorBuffer, sector, 1) != ESP_OK) {
      return 0;
    }
    input += chunk;
    position += chunk;
    remaining -= chunk;
  }
  return bufsize;
}

bool mscStartStop(uint8_t, bool, bool) {
  // Accept operating-system start, stop, and safe-eject requests. The card is
  // physically part of the dongle and is reinitialized on the next USB boot.
  return true;
}

bool initializeSdCard() {
  sdmmc_host_t host = SDMMC_HOST_DEFAULT();
  host.flags = SDMMC_HOST_FLAG_4BIT;
  host.slot = SDMMC_HOST_SLOT_1;
  host.max_freq_khz = POO_SDMMC_FREQUENCY_KHZ;

  sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
  slot.clk = static_cast<gpio_num_t>(POO_SDMMC_CLK_PIN);
  slot.cmd = static_cast<gpio_num_t>(POO_SDMMC_CMD_PIN);
  slot.d0 = static_cast<gpio_num_t>(POO_SDMMC_D0_PIN);
  slot.d1 = static_cast<gpio_num_t>(POO_SDMMC_D1_PIN);
  slot.d2 = static_cast<gpio_num_t>(POO_SDMMC_D2_PIN);
  slot.d3 = static_cast<gpio_num_t>(POO_SDMMC_D3_PIN);
  slot.width = 4;
  slot.flags = SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

  esp_err_t result = host.init();
  if (result != ESP_OK) {
    Serial.printf("SD host initialization failed: 0x%x\n", result);
    return false;
  }
  result = sdmmc_host_init_slot(host.slot, &slot);
  if (result != ESP_OK) {
    Serial.printf("SD slot initialization failed: 0x%x\n", result);
    host.deinit();
    return false;
  }
  result = sdmmc_card_init(&host, &card);
  if (result != ESP_OK) {
    Serial.printf("SD card initialization failed: 0x%x\n", result);
    host.deinit();
    return false;
  }
  if (card.csd.sector_size != kUsbSectorSize || card.csd.capacity == 0) {
    Serial.printf("Unsupported SD geometry: %u-byte sectors\n",
                  card.csd.sector_size);
    host.deinit();
    return false;
  }
  return true;
}
}  // namespace

bool usb_msc_begin() {
  cardReady = initializeSdCard();
  if (cardReady) {
    msc.vendorID("POO");
    msc.productID("SD VAULT");
    msc.productRevision("0.2");
    msc.onStartStop(mscStartStop);
    msc.onRead(mscRead);
    msc.onWrite(mscWrite);
    msc.mediaPresent(true);
    cardReady = msc.begin(card.csd.capacity, kUsbSectorSize);
    if (!cardReady) {
      msc.mediaPresent(false);
      Serial.println("USB mass-storage initialization failed");
    }
  }

  // Start the composite USB device even when the card is missing so the CDC
  // key protocol remains usable for diagnostics and document encryption.
  USB.begin();
  return cardReady;
}

bool usb_msc_ready() {
  return cardReady;
}

uint64_t usb_msc_capacity_bytes() {
  if (!cardReady) {
    return 0;
  }
  return static_cast<uint64_t>(card.csd.capacity) * card.csd.sector_size;
}
