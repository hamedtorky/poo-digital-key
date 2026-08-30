#include <Arduino.h>
#include <USB.h>
#include <USBMSC.h>
#include "esp_partition.h"

// Present the FFat partition as a read-only USB mass storage device.
// The image is a valid FAT filesystem built/uploaded via PlatformIO (buildfs/uploadfs).

static USBMSC msc;
static const esp_partition_t* ffat_part = nullptr;
static uint32_t sector_count = 0;
static constexpr uint32_t SECTOR_SIZE = 512;

static int32_t msc_read_func(uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize) {
  if (!ffat_part) return 0;
  uint32_t abs_off = lba * SECTOR_SIZE + offset;
  if (abs_off + bufsize > ffat_part->size) {
    // clamp or zero-fill beyond end
    uint32_t valid = (ffat_part->size > abs_off) ? (ffat_part->size - abs_off) : 0;
    if (valid) {
      if (esp_partition_read(ffat_part, abs_off, buffer, valid) != ESP_OK) return 0;
      memset((uint8_t*)buffer + valid, 0, bufsize - valid);
      return bufsize;
    }
    memset(buffer, 0, bufsize);
    return bufsize;
  }
  if (esp_partition_read(ffat_part, abs_off, buffer, bufsize) != ESP_OK) return 0;
  return bufsize;
}

static int32_t msc_write_func(uint32_t, uint32_t, uint8_t*, uint32_t) {
  // Read-only disk. Reject writes.
  return 0;
}

static bool msc_startstop_cb(uint8_t, bool, bool) {
  // Always accept start/stop/eject from host.
  return true;
}

void usb_msc_begin() {
  // Find the FFat partition (type=data, subtype=fat, label="ffat").
  ffat_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, "ffat");
  if (!ffat_part) {
    // No image present; skip MSC.
    return;
  }
  sector_count = (ffat_part->size + (SECTOR_SIZE - 1)) / SECTOR_SIZE;

  msc.vendorID("TDKEY");
  msc.productID("INSTALL");
  msc.productRevision("1.0");
  msc.onStartStop(msc_startstop_cb);
  msc.onRead(msc_read_func);
  msc.onWrite(msc_write_func);
  msc.mediaPresent(true);
  msc.begin(sector_count, SECTOR_SIZE);

  // Ensure USB controller is started so MSC is visible alongside CDC.
  USB.begin();
}
