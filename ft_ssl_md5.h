//
// Created by Evgen ARTESHCHUK on 10/2/18.
//

#ifndef FT_SSL_MD5_H
#define FT_SSL_MD5_H

#define BUFFSIZE 64

#define A 0x67452301
#define B 0xEFCDAB89
#define C 0x98BADCFE
#define D 0x10325476

#define FUNC_F(x, y, z) (x & y) | (~x & z)
#define FUNC_G(x ,y, z) (x & z) | (~z & y)
#define FUNC_H(x, y, z) x ^ y ^ z
#define FUNC_I(x, y, z) y ^ (~z | x)




#endif //FT_SSL_MD5_H
