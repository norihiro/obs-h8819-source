#pragma once

#include <stdint.h>
#include "common.h"

capdev_t *capdev_find_or_create(const char *device_name);
capdev_t *capdev_get_ref(capdev_t *dev);
void capdev_release(capdev_t *dev);

void capdev_link_source(capdev_t *dev, source_t *src, const int *channels);
void capdev_update_source(capdev_t *dev, source_t *src, const int *channels);
void capdev_unlink_source(capdev_t *dev, source_t *src);

void capdev_enum_devices(void (*cb)(const char *name, const char *description, void *param), void *param);
