
#include "ft_ssl_md5.h"

void md5_init(t_md5 *data)
{
    data->init.a = 1732584193;
    data->init.b = 4023233417;
    data->init.c = 2562383102;
    data->init.d = 271733878;
    data->a = 0;
    data->b = 0;
    data->c = 0;
    data->d = 0;
    data->t_len = 0;
    data->chnk = NULL;
}

void sha256_init(t_sha256 *data)
{
    data->init.h0 = 0x6A09E667;
    data->init.h1 = 0xBB67AE85;
    data->init.h2 = 0x3C6EF372;
    data->init.h3 = 0xA54FF53A;
    data->init.h4 = 0x510E527F;
    data->init.h5 = 0x9B05688C;
    data->init.h6 = 0x1F83D9AB;
    data->init.h7 = 0x5BE0CD19;
    data->h0 = 0;
    data->h1 = 0;
    data->h2 = 0;
    data->h3 = 0;
    data->h4 = 0;
    data->h5 = 0;
    data->h6 = 0;
    data->h7 = 0;
    data->t_len = 0x0;
    data->chnk = NULL;
}