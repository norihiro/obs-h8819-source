#pragma once

#include <stdint.h>
#include "common.h"

capdev_t *capdev_find_or_create(const char *device_name);
void capdev_release(capdev_t *dev);

void capdev_link_source(capdev_t *dev, source_t *src, uint32_t channel_mask);
void capdev_update_source(capdev_t *dev, source_t *src, uint32_t channel_mask);
void capdev_unlink_source(capdev_t *dev, source_t *src);
