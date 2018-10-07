#include "ft_ssl_md5.h"

static void print_hash_block(unsigned block)
{
    ft_printf("%.2x%.2x%.2x%.2x", (unsigned)((unsigned char)(block & 0xFF)),
              (unsigned)((unsigned char)(block >> 8) & 0xFF),
              (unsigned)((unsigned char)(block >> 16) & 0xFF),
              (unsigned)((unsigned char)(block >> 24) & 0xFF));
}

void print_hash(t_md5 *data)
{
    print_hash_block(data->init.a);
    print_hash_block(data->init.b);
    print_hash_block(data->init.c);
    print_hash_block(data->init.d);
}

void print_hash_sha256(t_sha256 *data)
{
    print_hash_block(uint32_to_b_endian(data->init.h0));
    print_hash_block(uint32_to_b_endian(data->init.h1));
    print_hash_block(uint32_to_b_endian(data->init.h2));
    print_hash_block(uint32_to_b_endian(data->init.h3));
    print_hash_block(uint32_to_b_endian(data->init.h4));
    print_hash_block(uint32_to_b_endian(data->init.h5));
    print_hash_block(uint32_to_b_endian(data->init.h6));
    print_hash_block(uint32_to_b_endian(data->init.h7));
}

uint8_t *r_chnk(uint8_t *chunk, ssize_t chunk_size, uint64_t total_size, uint64_t *chunks_qnt)
{
    uint8_t *final_chunk;

    *chunks_qnt = 0x01;
    if (chunk_size > 0x37)
        *chunks_qnt = 0x02;
    if (!(final_chunk = (uint8_t*)malloc(sizeof(uint8_t) * (*chunks_qnt * 0x40))))
        return (NULL);
    ft_memcpy(final_chunk, chunk, (size_t)chunk_size);
    final_chunk[chunk_size++] = 0x80;
    while ((chunk_size * 0x08) % 0X200 != 0x1c0)
        final_chunk[chunk_size++] = 0x0;
    ft_memcpy(&final_chunk[chunk_size], &total_size, 0x08);
    return (final_chunk);
}

