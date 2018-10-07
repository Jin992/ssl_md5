//
// Created by Evgen ARTESHCHUK on 10/6/18.
//
#include "ft_ssl_md5.h"

uint32_t uint32_to_b_endian(uint32_t val)
{
    uint8_t  c[4];

    if (is_bigendian())
        return val;
    else
    {
        c[0] = val & 255;
        c[1] = (val >> 8) & 255;
        c[2] = (val >> 16) & 255;
        c[3] = (val >> 24) & 255;
    }
    return (((uint32_t)c[0] << 24) + ((uint32_t)c[1] << 16) + \
            ((uint32_t)c[2] << 8) + c[3]);
}

uint64_t uint64_to_b_endian(uint64_t val)
{
    uint8_t  c[8];

    if (is_bigendian())
        return val;
    else
    {
        c[0] = val & 255;
        c[1] = (val >> 8) & 255;
        c[2] = (val >> 16) & 255;
        c[3] = (val >> 24) & 255;
        c[4] = (val >> 32) & 255;
        c[5] = (val >> 40) & 255;
        c[6] = (val >> 48) & 255;
        c[7] = (val >> 56) & 255;
    }
    return (((uint64_t)c[0] << 56) + ((uint64_t)c[1] << 48) + \
            ((uint64_t)c[2] << 40) + ((uint64_t)c[3] << 32) + \
            ((uint64_t)c[4] << 24) + ((uint64_t)c[5] << 16) + \
            ((uint64_t)c[6] << 8) + c[7]);
}