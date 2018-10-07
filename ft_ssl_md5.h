//
// Created by Evgen ARTESHCHUK on 10/2/18.
//

#ifndef FT_SSL_MD5_H
#define FT_SSL_MD5_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib/includes/libft.h"
#include "lib/includes/ft_printf.h"

#define CHUNK_SIZE 64

/*MD5 defines*/
#define FUNC_F(x, y, z) ((x & y) | ((~x) & z))
#define FUNC_G(x ,y, z) ((x & z) | (y & (~z)))
#define FUNC_H(x, y, z) (x ^ y ^ z)
#define FUNC_I(x, y, z) (y ^ (x | (~z)))

#define R_ONE(a, b, c, d, w, s, t) (b + ROL((a + FUNC_F(b,c,d) + w + t), s))
#define R_TWO(a, b, c, d, w, s, t) (b + ROL((a + FUNC_G(b,c,d) + w + t), s))
#define R_THREE(a, b, c, d, w, s, t) (b + ROL((a + FUNC_H(b,c,d) + w + t), s))
#define R_FOUR(a, b, c, d, w, s, t) (b + ROL((a + FUNC_I(b,c,d) + w + t), s))
/*MD5 defines end*/

/*SHA256 defines*/

#define FUNC_E0(a) (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22))
#define FUNC_E1(e) (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25))
#define FUNC_MA(a, b, c) ((a & b) ^ (a & c) ^ (b & c))
#define FUNC_CH(e, f, g) ((e & f) ^ ((~e) & g))
/*SHA256 defines end*/


#define ROL(a, s) ((a << s)|(a >> (32 - s)))
#define ROR(a, s) ((a >> s)|(a << (32 - s)))

static const int endian_check = 1;
#define is_bigendian()((*(char*)&endian_check) == 0)


static const unsigned T[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const unsigned T_SHA[] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static const unsigned S[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

typedef struct s_cntrl
{
    uint8_t         p;
    uint8_t         q;
    uint8_t         r;
    uint8_t         s;
    uint8_t         str_input;
    char            *command;
    struct s_cntrl  *next;
}               t_cntrl;

struct s_md_init
{
    unsigned            a;
    unsigned            b;
    unsigned            c;
    unsigned            d;
};

typedef struct s_md5
{
   struct s_md_init     init;
   unsigned             a;
   unsigned             b;
   unsigned             c;
   unsigned             d;
   ssize_t              read_n;
   uint64_t             t_len;
   uint8_t              buf[CHUNK_SIZE];
   uint8_t              *chnk;
   uint64_t             chnk_qnt;

}              t_md5;

struct s_sha_init
{
    unsigned            h0;
    unsigned            h1;
    unsigned            h2;
    unsigned            h3;
    unsigned            h4;
    unsigned            h5;
    unsigned            h6;
    unsigned            h7;
};

typedef struct          s_sha256
{
    struct s_sha_init   init;
    uint8_t             buf[CHUNK_SIZE];
    uint64_t            t_len;
    uint64_t            chnk_qnt;
    ssize_t             read_n;
    unsigned            h0;
    unsigned            h1;
    unsigned            h2;
    unsigned            h3;
    unsigned            h4;
    unsigned            h5;
    unsigned            h6;
    unsigned            h7;
    uint8_t             *chnk;

}                       t_sha256;


void        md5_init(t_md5 *data);
int         md5(int fd, t_cntrl *c_block);
void        first_round(t_md5 *d, const uint8_t *w);
void        second_round(t_md5 *d, const uint8_t *w);
void        third_round(t_md5 *d, const uint8_t *w);
void        four_round(t_md5 *d, const uint8_t *w);
void        print_hash(t_md5 *block);
void        sha256_init(t_sha256 *data);
int         sha256(int fd, t_cntrl *c_block);
void        print_hash_sha256(t_sha256 *data);
uint64_t    uint64_to_b_endian(uint64_t val);
uint32_t    uint32_to_b_endian(uint32_t val);
uint8_t     *r_chnk(uint8_t *chunk, ssize_t chunk_size, uint64_t total_size, uint64_t *chunks_qnt);


#endif //FT_SSL_MD5_H
