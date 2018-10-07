
#include "ft_ssl_md5.h"
#include <execinfo.h>


t_cntrl *cntrl_init(uint8_t str_input)
{
    t_cntrl *cntrl_block;
    if (!(cntrl_block = (t_cntrl*)malloc(sizeof(t_cntrl))))
        return NULL;
    cntrl_block->p = 0;
    cntrl_block->q = 0;
    cntrl_block->r = 0;
    cntrl_block->s = 0;
    cntrl_block->str_input = str_input;
    cntrl_block->command = NULL;
    cntrl_block->next = NULL;
    return cntrl_block;
}

void read_argv_input(int argc, char **argv, t_cntrl *c_block)
{
    size_t i = 2;

    while (argv[i] != 0)
    {
        if (ft_strlen(argv[i]) > 1)
        {
            if (argv[i][0] == '-' && c_block->str_input == 0)
            {
                if (argv[i][1] == 'p')
                    c_block->p = 1;
                else if (argv[i][1] == 'q')
                    c_block->q = 1;
                else if (argv[i][1] == 'r')
                    c_block->r = 1;
                else if (argv[i][1] == 's')
                    c_block->s = 1;
                else
                {
                    ft_printf("ft_ssl -%c undefined flag\n", argv[i][1]);
                    return;
                }
            }
            else
            {
                c_block->command = argv[i];
                if (argc - 1  != i)
                {
                    if (c_block->s == 0)
                        c_block->next = cntrl_init(1);
                    else
                        c_block->next = cntrl_init(0);
                    c_block = c_block->next;
                }
            }
        }
        else if (argv[i] != NULL)
        {
            c_block->command = argv[i];
            if (argc - 1  != i)
            {
                if (c_block->s == 0)
                    c_block->next = cntrl_init(1);
                else
                    c_block->next = cntrl_init(0);
                c_block = c_block->next;
            }
        }
        i++;
    }
}

void free_control(t_cntrl *list)
{
    t_cntrl *tmp;
    while (list != NULL)
    {
        tmp = list;
        list = list->next;
        free(tmp);
    }
}


int main(int argc, char **argv)
{
    t_cntrl *c_block;
    t_cntrl *head;
    int fd = 0;
    int (*funcs[3])(int, struct s_cntrl*) = {&md5, &sha256, 0};

   if (argc == 1) {
       return 1;
    }
    c_block = cntrl_init(0);
    head = c_block;
    read_argv_input(argc, argv, c_block);
    c_block = head;
    while (head != NULL)
    {
        ft_printf("P[%hhu] Q[%hhu] R[%hhu] S[%hhu] MSG[%s]\n", head->p, head->q, head->r, head->s, head->command == NULL ? "empty": head->command);

        head = head->next;
    }

    void *ptr = funcs[0];
    c_block->p = 1;
    if (ft_strstr(backtrace_symbols(&ptr, 100)[0], argv[1]))
    {
        //ft_printf("%s\n", backtrace_symbols(&ptr, 100)[0]);
        md5(fd, c_block);
    }
    else
        sha256(fd, &c_block);
    free_control(c_block);
    return (0);
}


