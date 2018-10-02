#include "lib/includes/libft.h"
#include "lib/includes/ft_printf.h"
#include "ft_ssl_md5.h"
#include <unistd.h>


void visualize_const()
{
    int n = 0;

    while (n < 64)
    {
        
        n++;
    }
}
char *ft_md5(char *msg, ssize_t size, size_t *len)
{


    len = ft_strlen(msg);

}




int main(int argc, char **argv)
{
    ssize_t read_n;
    int fd;
    char buff[BUFFSIZE];

    while ((read_n = read(fd, buff, 64)) > 0)
    {
        ft_md5(buff, read_n);
    }
    return (0);
}
