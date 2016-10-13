/*
 ============================================================================
 Name        : encdec.c
 Author      : Manisha Agrawal
 Description  : You are given a plaintext and a ciphertext. Numbers in the
IV are all zeros (not the ASCII character `0'). The key used to encrypt this
plaintext is an English word shorter than 16 characters; Since the word has
less than 16 characters (i.e. 128 bits), space characters (hexadecimal value 0x20)
are appended to the end of the word to form a key of 128 bits. Your goal is to write
a program to find out this key.
Ciphertype :  aes-128-cbc

AES encrypt. do_encrypt is 1 for encryption and 0 for decryption

 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define DICTIONARY "words_dict.txt" //dictionary file

char inText[] = "This is a top secret."; //Input
char cipherText[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
unsigned char iv[16] = { 0 } ;

int cipher_hex(unsigned char *buf, int len, FILE *outFile)
{
    unsigned char buffer[1024]="";
    unsigned char *pbuffer = buffer;
	char x='\n';

	for ( int i = 0; i < len; i++ )
	{
		fprintf(outFile,"%02x",buf[i]);
		sprintf(pbuffer, "%02x", buf[i]);
		pbuffer +=2;
	}
	fprintf(outFile,"%c",x);

    //If cipher text match return 1
    if(!strcmp(buffer, cipherText))
    	return 1;
	return 0;
}

int main()
{
	char key[1024];
	FILE *words, *outFile;
	unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int outlen, tmplen, i;
	EVP_CIPHER_CTX ctx;

	words = fopen(DICTIONARY, "r");
	outFile = fopen("ciphertext.txt", "w+"); //file to store ciphers
	if( key < 0 || outFile < 0 )
	{
		perror ("Cannot open file");
		exit(1);
	}

	EVP_CIPHER_CTX_init(&ctx);
	while ( fgets(key,16, words) )
	{
		if(strlen(key)>=16)
			continue;

		for(i=strlen(key)-1;i<16;i++) //if key is less than 16 than pad with spaces
				key[i]=' ';
		key[i] = '\0';

	    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);

		if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inText, strlen(inText)))
		{
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		if(!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
		{
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		outlen += tmplen;
        
		if(cipher_hex(outbuf, outlen, outFile)) //convert raw cipher to hex value
		{
			printf("Key found!! Key : %s\n",key);
			break;
		}
	}

	fclose(words);
	fclose(outFile);

	return 1;
}


