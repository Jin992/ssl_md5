#include "ft_ssl_md5.h"

void first_round(t_md5 *d, const uint8_t *w)
{
    d->a = R_ONE(d->a, d->b, d->c, d->d, *(unsigned *)&w[0], S[0], T[0]);
    d->d = R_ONE(d->d, d->a, d->b, d->c, *(unsigned *)&w[4], S[1], T[1]);
    d->c = R_ONE(d->c, d->d, d->a, d->b, *(unsigned *)&w[8], S[2], T[2]);
    d->b = R_ONE(d->b, d->c, d->d, d->a, *(unsigned *)&w[12], S[3], T[3]);
    d->a = R_ONE(d->a, d->b, d->c, d->d, *(unsigned *)&w[16], S[4], T[4]);
    d->d = R_ONE(d->d, d->a, d->b, d->c, *(unsigned *)&w[20], S[5], T[5]);
    d->c = R_ONE(d->c, d->d, d->a, d->b, *(unsigned *)&w[24], S[6], T[6]);
    d->b = R_ONE(d->b, d->c, d->d, d->a, *(unsigned *)&w[28], S[7], T[7]);
    d->a = R_ONE(d->a, d->b, d->c, d->d, *(unsigned *)&w[32], S[8], T[8]);
    d->d = R_ONE(d->d, d->a, d->b, d->c, *(unsigned *)&w[36], S[9], T[9]);
    d->c = R_ONE(d->c, d->d, d->a, d->b, *(unsigned *)&w[40], S[10], T[10]);
    d->b = R_ONE(d->b, d->c, d->d, d->a, *(unsigned *)&w[44], S[11], T[11]);
    d->a = R_ONE(d->a, d->b, d->c, d->d, *(unsigned *)&w[48], S[12], T[12]);
    d->d = R_ONE(d->d, d->a, d->b, d->c, *(unsigned *)&w[52], S[13], T[13]);
    d->c = R_ONE(d->c, d->d, d->a, d->b, *(unsigned *)&w[56], S[14], T[14]);
    d->b = R_ONE(d->b, d->c, d->d, d->a, *(unsigned *)&w[60], S[15], T[15]);
}

void second_round(t_md5 *d, const uint8_t *w)
{
    d->a = R_TWO(d->a, d->b, d->c, d->d, *(unsigned *)&w[4], S[16], T[16]);
    d->d = R_TWO(d->d, d->a, d->b, d->c, *(unsigned *)&w[24], S[17], T[17]);
    d->c = R_TWO(d->c, d->d, d->a, d->b, *(unsigned *)&w[44], S[18], T[18]);
    d->b = R_TWO(d->b, d->c, d->d, d->a, *(unsigned *)&w[0], S[19], T[19]);
    d->a = R_TWO(d->a, d->b, d->c, d->d, *(unsigned *)&w[20], S[20], T[20]);
    d->d = R_TWO(d->d, d->a, d->b, d->c, *(unsigned *)&w[40], S[21], T[21]);
    d->c = R_TWO(d->c, d->d, d->a, d->b, *(unsigned *)&w[60], S[22], T[22]);
    d->b = R_TWO(d->b, d->c, d->d, d->a, *(unsigned *)&w[16], S[23], T[23]);
    d->a = R_TWO(d->a, d->b, d->c, d->d, *(unsigned *)&w[36], S[24], T[24]);
    d->d = R_TWO(d->d, d->a, d->b, d->c, *(unsigned *)&w[56], S[25], T[25]);
    d->c = R_TWO(d->c, d->d, d->a, d->b, *(unsigned *)&w[12], S[26], T[26]);
    d->b = R_TWO(d->b, d->c, d->d, d->a, *(unsigned *)&w[32], S[27], T[27]);
    d->a = R_TWO(d->a, d->b, d->c, d->d, *(unsigned *)&w[52], S[28], T[28]);
    d->d = R_TWO(d->d, d->a, d->b, d->c, *(unsigned *)&w[8], S[29], T[29]);
    d->c = R_TWO(d->c, d->d, d->a, d->b, *(unsigned *)&w[28], S[30], T[30]);
    d->b = R_TWO(d->b, d->c, d->d, d->a, *(unsigned *)&w[48], S[31], T[31]);
}

void third_round(t_md5 *d, const uint8_t *w)
{
    d->a = R_THREE(d->a, d->b, d->c, d->d, *(unsigned *)&w[20], S[32], T[32]);
    d->d = R_THREE(d->d, d->a, d->b, d->c, *(unsigned *)&w[32], S[33], T[33]);
    d->c = R_THREE(d->c, d->d, d->a, d->b, *(unsigned *)&w[44], S[34], T[34]);
    d->b = R_THREE(d->b, d->c, d->d, d->a, *(unsigned *)&w[56], S[35], T[35]);
    d->a = R_THREE(d->a, d->b, d->c, d->d, *(unsigned *)&w[4], S[36], T[36]);
    d->d = R_THREE(d->d, d->a, d->b, d->c, *(unsigned *)&w[16], S[37], T[37]);
    d->c = R_THREE(d->c, d->d, d->a, d->b, *(unsigned *)&w[28], S[38], T[38]);
    d->b = R_THREE(d->b, d->c, d->d, d->a, *(unsigned *)&w[40], S[39], T[39]);
    d->a = R_THREE(d->a, d->b, d->c, d->d, *(unsigned *)&w[52], S[40], T[40]);
    d->d = R_THREE(d->d, d->a, d->b, d->c, *(unsigned *)&w[0], S[41], T[41]);
    d->c = R_THREE(d->c, d->d, d->a, d->b, *(unsigned *)&w[12], S[42], T[42]);
    d->b = R_THREE(d->b, d->c, d->d, d->a, *(unsigned *)&w[24], S[43], T[43]);
    d->a = R_THREE(d->a, d->b, d->c, d->d, *(unsigned *)&w[36], S[44], T[44]);
    d->d = R_THREE(d->d, d->a, d->b, d->c, *(unsigned *)&w[48], S[45], T[45]);
    d->c = R_THREE(d->c, d->d, d->a, d->b, *(unsigned *)&w[60], S[46], T[46]);
    d->b = R_THREE(d->b, d->c, d->d, d->a, *(unsigned *)&w[8], S[47], T[47]);
}

void four_round(t_md5 *d, const uint8_t *w)
{
    d->a = R_FOUR(d->a, d->b, d->c, d->d, *(unsigned *)&w[0], S[48], T[48]);
    d->d = R_FOUR(d->d, d->a, d->b, d->c, *(unsigned *)&w[28], S[49], T[49]);
    d->c = R_FOUR(d->c, d->d, d->a, d->b, *(unsigned *)&w[56], S[50], T[50]);
    d->b = R_FOUR(d->b, d->c, d->d, d->a, *(unsigned *)&w[20], S[51], T[51]);
    d->a = R_FOUR(d->a, d->b, d->c, d->d, *(unsigned *)&w[48], S[52], T[52]);
    d->d = R_FOUR(d->d, d->a, d->b, d->c, *(unsigned *)&w[12], S[53], T[53]);
    d->c = R_FOUR(d->c, d->d, d->a, d->b, *(unsigned *)&w[40], S[54], T[54]);
    d->b = R_FOUR(d->b, d->c, d->d, d->a, *(unsigned *)&w[4], S[55], T[55]);
    d->a = R_FOUR(d->a, d->b, d->c, d->d, *(unsigned *)&w[32], S[56], T[56]);
    d->d = R_FOUR(d->d, d->a, d->b, d->c, *(unsigned *)&w[60], S[57], T[57]);
    d->c = R_FOUR(d->c, d->d, d->a, d->b, *(unsigned *)&w[24], S[58], T[58]);
    d->b = R_FOUR(d->b, d->c, d->d, d->a, *(unsigned *)&w[52], S[59], T[59]);
    d->a = R_FOUR(d->a, d->b, d->c, d->d, *(unsigned *)&w[16], S[60], T[60]);
    d->d = R_FOUR(d->d, d->a, d->b, d->c, *(unsigned *)&w[44], S[61], T[61]);
    d->c = R_FOUR(d->c, d->d, d->a, d->b, *(unsigned *)&w[8], S[62], T[62]);
    d->b = R_FOUR(d->b, d->c, d->d, d->a, *(unsigned *)&w[36], S[63], T[63]);
}

