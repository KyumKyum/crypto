#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128
int BN_xor(BIGNUM *b_r, int bits, const BIGNUM *b_a, const BIGNUM *b_b)
{
   //error
   if(b_r==NULL || b_a == NULL || b_b == NULL) 
      return 0;
   //bytes = bits / 8
   int i, bytes = bits >> 3;
   //calloc for type casting(BIGNUM to U8)
   U8 *r = (U8*)calloc(bytes,sizeof(U8));
   U8 *a = (U8*)calloc(bytes,sizeof(U8));
   U8 *b = (U8*)calloc(bytes,sizeof(U8));
   //BN_num_bytes(a) : return a's bytes 
   int byte_a = BN_num_bytes(b_a);
   int byte_b = BN_num_bytes(b_b);
   //difference between A and B
   int dif = abs(byte_a-byte_b);
   //minimum
   int byte_min = (byte_a < byte_b)? byte_a : byte_b;
   //type casting(BIGNUM to U8)
   BN_bn2bin(b_a,a);
   BN_bn2bin(b_b,b);
   //xor compute
   for(i=1;i<=byte_min;i++)
      r[bytes - i] = a[byte_a - i] ^ b[byte_b - i];
   for(i=1;i<=dif;i++)
      r[bytes - byte_min - i] = (byte_a>byte_b)? a[dif-i] : b[dif-i];
   //type casting(U8 to BIGNUM)
   BN_bin2bn(r,bytes,b_r);
   //Free memory
   free(a);
   free(b);
   free(r);
   return 1;//correct
}
int Gen(AES_KEY *enckey, int bits)
{
   if (enckey == NULL || bits <= 0) return 0;
   int bytes = bits >> 3;

   //*** write your code from here

   //choose uniform BN key
	BIGNUM *key = BN_new();
	BN_rand(key, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

   //type casting BN key -> U8(binary) key
	U8 *user_key = (U8*)calloc(bytes, sizeof(U8));
	BN_bn2bin(key, user_key);

   //AES encrpytion key setting
	AES_set_encrypt_key(user_key, bits, enckey);
	
	BN_free(key);
	free(user_key);

   //*** end

   return 1;

}
U8 ** Enc(AES_KEY *k, int bits, U8 *m) 
{
   int i, bytes = bits >> 3;
   U8 **c = (U8 **)calloc(2, sizeof(U8*)); // C = [r, F_k(r)]
   for (i = 0; i < 2; i++)
      c[i] = (U8 *)calloc(bytes, sizeof(U8)); //* Initialize C[0], C[1] (r, F(r))

   //*** write your code from here
   //choose uniform BN r
	BIGNUM *BN_r = BN_new();
	BN_rand(BN_r, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
   
    //print BN r
    printf("r: %s\n", BN_bn2hex(BN_r));
	
    //setting C1
	BN_bn2bin(BN_r, c[0]); //(BIGNUM -> U8 (Binary Form))

   //AES Encryption F_k(r)
	U8 *Fk_r = (U8*)calloc(bytes, sizeof(U8));
	AES_encrypt(c[0], Fk_r, k);

   //type casting U8 F_k(r)-> BN F_k(r)    for F_k(r) xor m
	BIGNUM *BN_Fk_r = BN_new();
	BN_bin2bn(Fk_r, strlen(Fk_r), BN_Fk_r);
	
    //print F_k(r)
	printf("Fkr: %s\n", BN_bn2hex(BN_Fk_r));

   //type casting U8 m -> BN m             for F_k(r) xor m
	BIGNUM *BN_m = BN_new();
	BN_bin2bn(m, strlen(m), BN_m);

   //C2 = F_k(r) xor m
	BIGNUM *BN_C2 = BN_new();
	BN_xor(BN_C2, bits, BN_Fk_r, BN_m);
   
    //setting C2
	BN_bn2bin(BN_C2, c[1]);
	
	BN_free(BN_r);
	BN_free(BN_Fk_r);
	BN_free(BN_m);
	BN_free(BN_C2);
	free(Fk_r);
	
   //*** end

   return c;
}
U8 *Dec(AES_KEY *k, int bits, U8 **C)
{
   int bytes = bits >> 3;
   U8 *M = (U8*)calloc(bytes, sizeof(U8));

   //*** write your code from here

    //compute F_k(C1)
	U8 *Fk_C1 = (U8*)calloc(bytes, sizeof(U8));
	AES_encrypt(C[0], Fk_C1, k);
    
    //type casting U8 F_k(C1) -> BN F_k(C1)       for  F_k(C1) xor C2
    BIGNUM *BN_Fk_C1 = BN_new();
	BN_bin2bn(Fk_C1, strlen(Fk_C1), BN_Fk_C1);
	
   //print F_k(C1)
	printf("Fkc: %s\n", BN_bn2hex(BN_Fk_C1));

    //type casting U8 C[1] -> BN C2                for  F_k(C1) xor C2
    BIGNUM *BN_C2 = BN_new();
	BN_bin2bn(C[1], strlen(C[1]), BN_C2);
	
   //compute F_k(C1) xor C2 = m   and   type casting  BN m -> U8 M
	U8 *BN_M = (U8 *)calloc(bytes, sizeof(U8));
	BN_xor(BN_M, bits, BN_Fk_C1, BN_C2);
	BN_bn2bin(BN_M, M);
	
	BN_free(BN_Fk_C1);
	BN_free(BN_C2);
	free(BN_M);
	free(Fk_C1);
   //*** end

   return M;
}
int main(int argc, char* argv[]) {
   int i;
   AES_KEY enckey; // AES encryption key
   U8 *m = "CPA-secure";
   U8 *dec = (U8*)calloc(BYTES,sizeof(U8));
   
   Gen(&enckey,BITS);
   U8 **c = Enc(&enckey,BITS,m);
   U8 *d_m = Dec(&enckey,BITS,c);
   
   printf("C1 : ");
   for(i=0;i<BYTES;i++)
      printf("%02X",c[0][i]);
   printf("\n");
   printf("C2 : ");
   for(i=0;i<BYTES;i++)
      printf("%02X",c[1][i]);
   printf("\n");
   printf("Dec : %s\n", d_m);
   
   free(c[0]);
   free(c[1]);
   free(c);
   return 0;
}