#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256


void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}



int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *q = BN_new();
BIGNUM *n = BN_new();
BIGNUM *e = BN_new();
BIGNUM *phi = BN_new();
BIGNUM *p_1 = BN_new();
BIGNUM *q_1 = BN_new();
BIGNUM *one = BN_new();
BIGNUM *d = BN_new();

BN_dec2bn(&one, "1");


BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_hex2bn(&e, "0D88C3");

// n = pq
BN_mul(n, p, q, ctx);
printBN("public key", n);

BN_sub(p_1, p, one);
BN_sub(q_1, q, one);
BN_mul(phi, p_1, q_1, ctx);


BN_mod_inverse(d, e, phi, ctx);
printBN("private key", d);

BN_clear_free(p);
BN_clear_free(q);
BN_clear_free(n);
BN_clear_free(phi);
BN_clear_free(e);
BN_clear_free(d);
BN_clear_free(p_1);
BN_clear_free(q_1);

return 0;
}
