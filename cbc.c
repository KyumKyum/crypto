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
int cbcEnc(U8 *key, const U8 *msg, U8 *cbc) 
{
    int i, j, msg_len = strlen(msg), bottom = BYTES - 1;
    U8 IV[BYTES], msg_block[17] = {0}, PRF[BYTES];
	U8 XOR[BYTES]; //* To store xor value with c[i-1] ^ m[i]
    AES_KEY enckey;

    AES_set_encrypt_key(key, BITS, &enckey); //* c0 <- IV
    if (RAND_bytes(IV, 16) <= 0) //* Randomly pick 16byte value.
        printf("random error\n");
	//* First 16 byte: filled with IV (c0)
    memcpy(cbc, IV, BYTES); //* C0 Filled.

	//* Encrypt by block .
	//* CBC - Cipher Block Chaining
    for (i = 0; i < msg_len / BYTES; i++) //* Encrypt by block size. (divide by BYTES(16))
    {
		//* Step 1) c[i-1] ^ m[i]
		for(j = 0; j < BYTES; j++){
			XOR[j] = cbc[(i * BYTES) + j] ^ msg[(i * BYTES) + j]; //* Save XOR value.
		}
		//* Step 2) F(k)
        AES_encrypt(XOR, PRF, &enckey);
		
		//* Step 3) Store F(k) to c[i].
        for (j = 0; j < BYTES; j++)
            cbc[(i + 1) * BYTES + j] = PRF[j]; //* Save c[i] 
    }
	
	//* Padding
    int mb_len = strlen(msg + i * BYTES);
    int pad = BYTES - mb_len; 
    memcpy(msg_block, msg + i * BYTES, BYTES);
    for (j = bottom; j >= mb_len; j--)
        msg_block[j] = pad;
    printf("m_t \t\t: "); //* Print Pad
    for (j = 0; j < BYTES; j++)
        printf("%02X", msg_block[j]);
    printf("\n");
    msg_block[BYTES] = 0;
    j = bottom;
    for(j = 0; j < BYTES; j++){
		XOR[j] = cbc[(i * BYTES) + j] ^ msg_block[j]; //* Save XOR value. - Padded value
	}
	
    AES_encrypt(XOR, PRF, &enckey);
	
    for (j = 0; j < BYTES; j++)
        cbc[(i + 1) * BYTES + j] = PRF[j]; //* Update last value

    return (i + 2) * BYTES;
}

// U8 *key       : key for AES_set_decrypt_key
// const U8 *ctr : ciphertext to be decrypted
// int ct_len    : length of ciphertext
// U8* dec_msg   : decrypted message (output)
// returns length of decrypted message
int cbcDec(U8 *key, const U8 *cbc, int cb_len, U8 *dec_msg)
{
    U8 IV[BYTES] = {0};
	U8 Cb[BYTES] = {0}; //* Block in ci
	U8 IVS[BYTES] = {0}; //* Save inversed F[ci] (decrypted ci)
    int i, j, bottom = BYTES - 1;
    AES_KEY deckey;
    AES_set_decrypt_key(key, BITS, &deckey);

    memcpy(IV, cbc, BYTES);
	//* Get IV from c[0]
	
    for (i = cb_len / BYTES; i > 0; i--) //* Starts from rear.
    {
		//* Decryption Start:
		//* Step 1: Get ith block of c
		for(j = 0; j < BYTES; j++){
			Cb[j] = cbc[(i * BYTES) + j]; //* Get ith block of ciphertext
		}
		
		//* Step 2: Decrypt c[i] (aes_decrypt)
		AES_decrypt(Cb, IVS, &deckey); //* IVS: Inversed Result
		
		//* Step 3: XOR with ci-1, save it in dec_msg;
		
		for(j = 0; j < BYTES; j++){
			dec_msg[((i - 1) * BYTES) + j] = cbc[((i - 1) * BYTES) + j] ^ IVS[j]; //* ci-1 ^ F-1(ci);
			//* Need to save one block less than cbc <- IV is not required.
		}
		
    }

    U8 pad = dec_msg[cb_len - 17]; //* Remove Pad
    if (pad <= 0 || pad > BYTES)
        return 0;
    printf("Dec m_t \t: ");
    for (j = 0; j < BYTES; j++)
        printf("%02X", dec_msg[((cb_len/BYTES) - 2) * BYTES + j]); //* -2 from block length: removes pad & IV
    printf("\n");
    for (j = 0; j < pad; j++)
        dec_msg[cb_len - 17 - j] = 0;
    return (strlen(dec_msg));
}

int main(int argc, char *argv[])
{
	printf("---------- CBC ENC & DEC ----------\n");
    RAND_status(); // random seed
    U8 key[BYTES];
    U8 m[] = "If F is a pseudorandom function, then CTR mode is CPA-secure";
    int cbc_len = (strlen(m) % BYTES == 0) ? BYTES * (strlen(m) / BYTES + 1) : BYTES * (strlen(m) / BYTES + 2);
    U8 *cbc = (U8 *)calloc(cbc_len, sizeof(U8));
    Gen(key);
    cbc_len = cbcEnc(key, m, cbc);
    U8 *dec_msg = (U8 *)calloc(cbc_len - BYTES, sizeof(U8));
    int m_len = cbcDec(key, cbc, cbc_len, dec_msg);
    printf("Enc \t\t: ");
    for (int i = 0; i < cbc_len; i++)
        printf("%02X", cbc[i]);
    printf("\n");
    if (m_len > 0)
        printf("Decryption \t: %s\n", dec_msg);
    else
        printf("Error!!!\n");
    free(cbc);
    free(dec_msg);
    return 0;
}