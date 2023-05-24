#include <stdio.h>
#include <openssl/bn.h>

int main(int argc, char* argv[]) {
	//printf("Hello, goorm!\n");
	BIGNUM *a = BN_new(); //* Memory Allocation for big bit
	BIGNUM *b; //* Hugh amount of bit.`
	b = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *key = BN_new();
	
	BN_set_word(a,255);
	BN_set_word(b,128);
	
	BN_rand(key, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY); //* Random

	
	printf("a as hex: %s\n", BN_bn2hex(a));
	printf("a as hex :%s\n", BN_bn2dec(a));
	printf("rand: %s\n", BN_bn2hex(key));
	
	unsigned char *bin = (unsigned char*)calloc(16,sizeof(unsigned char));
	
	int len = BN_bn2bin(a,bin);
	for(int i = 0; i < len; i++){
      printf("%x", bin[i]);
	}
	printf("\n");
	
	printf("b as hex: %s\n", BN_bn2hex(b));
	printf("b as hex :%s\n", BN_bn2dec(b));
	
	BN_add(c,a,b);
	printf("A + B = %s\n", BN_bn2dec(c));
	
	//* ctx: for complex computation - mul, div..
	BN_CTX *ctx = BN_CTX_new();
	BN_mul(c,a,b,ctx);
	BN_CTX_free(ctx);
	printf("A * B = %s\n", BN_bn2dec(c));
	
	
	BN_free(a);
	BN_free(b);
	BN_free(c);
	BN_free(key);
	
	return 0;
}