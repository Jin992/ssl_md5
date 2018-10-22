#include "ft_ssl_md5.h"



static void _md5(uint8_t *block, t_md5 *data)
{
    data->a = data->init.a;
    data->b = data->init.b;
    data->c = data->init.c;
    data->d = data->init.d;
    first_round(data, block);
    second_round(data, block);
    third_round(data, block);
    four_round(data, block);
    data->init.a += data->a;
    data->init.b += data->b;
    data->init.c += data->c;
    data->init.d += data->d;
}






int    md5(t_cntrl *c_block)
{
    t_md5           dt;

    md5_init(&dt);
    while (1)
    {
        if (msg_reader(c_block, &dt.t_len, dt.buf, &dt.read_n))
            break;
        if (!(dt.chnk = r_chnk(dt.buf, dt.read_n, dt.t_len, &dt.chnk_qnt)))
            return (0x01);
        _md5(dt.chnk, &dt);
        if (dt.chnk_qnt == 0x02)
            _md5(&dt.chnk[0x40], &dt);
        if (!dt.chnk)
        {
            free(dt.chnk);
            dt.chnk = NULL;
        }
     }
        if (c_block->p)
            write(STDOUT_FILENO, "\n", 1);
        print_hash(&dt);
    return (0);
}


