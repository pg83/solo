#include "hash.h"

#include <stdint.h>

size_t splitMix64(size_t value) noexcept {
    uint64_t mixed = value + UINT64_C(0x9e3779b97f4a7c15);

    mixed = (mixed ^ (mixed >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    mixed = (mixed ^ (mixed >> 27)) * UINT64_C(0x94d049bb133111eb);

    return mixed ^ (mixed >> 31);
}
