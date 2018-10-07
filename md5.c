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

ssize_t read_str(char *str, void *buff, size_t buff_size, size_t check_point)
{
    ssize_t len;
    ssize_t read_n;

    read_n = check_point;
    len = ft_strlen(&str[read_n]);
    ft_memset(buff, 0, buff_size);
    if (len == 0 )
        return 0;
    if (len - check_point >= CHUNK_SIZE)
    {
        ft_memcpy(buff, &str[read_n], CHUNK_SIZE);
        read_n =  CHUNK_SIZE;
    }
    else
    {
        ft_memcpy(buff, &str[read_n], len);
        read_n = len;
    }
    return read_n;
}


int    md5(int fd, t_cntrl *c_block)
{
    t_md5           dt;
    static size_t minus_one;

    md5_init(&dt);
    while (1)
    {
        if (c_block->s)
            dt.read_n = read_str(c_block->command, dt.buf, CHUNK_SIZE, dt.t_len / 8);
        else
            dt.read_n = read(fd, dt.buf, CHUNK_SIZE);
        if (minus_one)
            break;
        if ((dt.read_n <= 0 || dt.read_n < CHUNK_SIZE)&& minus_one == 0)
            minus_one = 1;
        if (c_block->p)
            write(STDOUT_FILENO, dt.buf, (size_t) dt.read_n);
         dt.t_len += dt.read_n * 8;
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

