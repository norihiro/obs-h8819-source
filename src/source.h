#pragma once

#include <stdint.h>
#include "common.h"

void source_add_audio(source_t *s, float **data, int n_samples, uint64_t timestamp);
