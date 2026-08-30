#pragma once

#include <stdint.h>

// Exposes the T-Dongle S3 SD card as a writable USB mass-storage disk while
// keeping the existing USB CDC key protocol active.
bool usb_msc_begin();
bool usb_msc_ready();
uint64_t usb_msc_capacity_bytes();
