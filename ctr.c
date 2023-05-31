#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128

//* Key Generator: AES Seed Key.
int Gen(U8 *key)
{
    if (key == NULL)
        return 0;
    RAND_bytes(key, BYTES);
    return 1;
}

// U8 *key       : key for AES_set_encrypt_key
// const U8 *msg : message to be encrypted
// U8 *ctr       : ciphertext (output)
// returns length of ciphertext
int ctrEnc(U8 *key, const U8 *msg, U8 *ctr) 
{
    int i, j, msg_len = strlen(msg), bottom = BYTES - 1;
    U8 IV[BYTES], msg_block[17] = {0}, PRF[BYTES];
    AES_KEY enckey;

    AES_set_encrypt_key(key, BITS, &enckey); //* c0 <- IV
    if (RAND_bytes(IV, 16) <= 0) //* Randomly pick 16byte value.
        printf("random error\n");
    memcpy(ctr, IV, BYTES); //* C0 Filled.

    for (i = 0; i < msg_len / BYTES; i++) //* Encrypt by block size.
    {
        j = bottom;
        do
        {
            IV[j] += 1;
        } while (IV[j--] == 0 && j != 0);
        AES_encrypt(IV, PRF, &enckey);
        for (j = 0; j < BYTES; j++)
            ctr[(i + 1) * BYTES + j] = PRF[j] ^ msg[(i * BYTES) + j]; //* mi ^ F(k) = ci
    }
    int mb_len = strlen(msg + i * BYTES);
    int pad = BYTES - mb_len; //* Byte
    memcpy(msg_block, msg + i * BYTES, BYTES);
    for (j = bottom; j >= mb_len; j--)
        msg_block[j] = pad;
    printf("m_t \t\t: ");
    for (j = 0; j < BYTES; j++)
        printf("%02X", msg_block[j]);
    printf("\n");
    msg_block[BYTES] = 0;
    j = bottom;
    do
    {
        IV[j] += 1;
    } while (IV[j--] == 0 && j != 0);
    AES_encrypt(IV, PRF, &enckey);
    for (j = 0; j < BYTES; j++)
        ctr[(i + 1) * BYTES + j] = msg_block[j] ^ PRF[j];

    return (i + 2) * BYTES;
}

// U8 *key       : key for AES_set_encrypt_key
// const U8 *ctr : ciphertext to be decrypted
// int ct_len    : length of ciphertext
// U8* dec_msg   : decrypted message (output)
// returns length of decrypted message
int ctrDec(U8 *key, const U8 *ctr, int ct_len, U8 *dec_msg)
{
    U8 IV[BYTES] = {0}, PRF[BYTES] = {0};
    int i, j, bottom = BYTES - 1;
    AES_KEY enckey;
    AES_set_encrypt_key(key, BITS, &enckey);

    memcpy(IV, ctr, BYTES);
    for (i = 1; i < ct_len / BYTES; i++)
    {
        j = bottom;
        do
        {
            IV[j] += 1;
        } while (IV[j--] == 0 && j != 0);
        AES_encrypt(IV, PRF, &enckey);
        for (j = 0; j < BYTES; j++)
            dec_msg[(i - 1) * BYTES + j] = ctr[(i * BYTES) + j] ^ PRF[j];
    }
	
	printf("i: %d\n", i);
    U8 pad = dec_msg[ct_len - 17]; //* Remove Pad
    if (pad <= 0 || pad > BYTES)
        return 0;
    printf("Dec m_t \t: ");
    for (j = 0; j < BYTES; j++)
        printf("%02X", dec_msg[(i - 2) * BYTES + j]);
    printf("\n");
    for (j = 0; j < pad; j++)
        dec_msg[ct_len - 17 - j] = 0;
    return (strlen(dec_msg));
}

int main(int argc, char *argv[])
{
    RAND_status(); // random seed
    U8 key[BYTES];
    U8 m[] = "If F is a pseudorandom function, then CTR mode is CPA-secure";
    int ctr_len = (strlen(m) % BYTES == 0) ? BYTES * (strlen(m) / BYTES + 1) : BYTES * (strlen(m) / BYTES + 2);
    U8 *ctr = (U8 *)calloc(ctr_len, sizeof(U8));
    Gen(key);
    ctr_len = ctrEnc(key, m, ctr);
    U8 *dec_msg = (U8 *)calloc(ctr_len - BYTES, sizeof(U8));
    int m_len = ctrDec(key, ctr, ctr_len, dec_msg);
    printf("Enc \t\t: ");
    for (int i = 0; i < ctr_len; i++)
        printf("%02X", ctr[i]);
    printf("\n");
    if (m_len > 0)
        printf("Decryption \t: %s\n", dec_msg);
    else
        printf("Error!!!\n");
    free(ctr);
    free(dec_msg);
    return 0;
}