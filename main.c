/* 20170201 NaJiwoong */
/* 2020 April 23 */

/*   Environment
 *	 
 *	 Ubuntu 16.04.12
 *	 gcc 5.4.0 
 */

/* 		Execution
 *
 *	 	"make"
 *	 	 - make execution file, and output.txt
 *	 	"make clean"
 *	 	 - clean execution file, and output.txt
 */

/*	Reference	for encryption code (aes-128.c)
 *
 *	Open source code from
 *	<openluopworld>
 *	-"https://github.com/openluopworld/aes_128"
 *	
 * 	- License attached -
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "aes-128.h"


/* Function for hamming distance */
int hamming(uint8_t *a, uint8_t *b){
	int dist;
	int i, j;
	for (i = 0; i < 16; i++){
		for (j = 0; j < 8; j++){
			uint8_t abit, bbit;
			abit = (a[i] >> j) & 1;
			bbit = (b[i] >> j) & 1;
			dist += (abit == bbit) ? 0 : 1;
		}
	}
	return dist;
}

/* Function for test */
/* First flag for (i) or (ii), and second flag for [a] or [b] */
void test(FILE *fp, int flag, int flag2){
	int i;

	uint8_t key[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		//0x32, 0x30, 0x31, 0x32, 0x31, 0x30, 0x36, 0x30,
		//0x30, 0x32, 0x4B, 0x4B, 0x57, 0x4B, 0x4B, 0x57,
	};

	uint8_t plaintext[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		//0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		//0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
	};

	uint8_t plaintext2[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		//0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		//0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
	};

	// If flag2 == 1, generate random plaintext and key
	if (flag2 == 1){						
		for (i = 0; i < 8; i++){
			srand((unsigned int)(time(NULL)+i));
			unsigned short rv = rand();
			plaintext[2*i] = (rv >> 8) & 0xFF;
			plaintext[2*i+1] = rv & 0xFF;
			plaintext2[2*i] = plaintext[2*i];
			plaintext2[2*i+1] = plaintext[2*i+1];

			srand((unsigned int)(time(NULL)+41));
			rv = rand();
			key[2*i] = (rv >> 8) & 0xFF;
			key[2*i+1] = rv & 0xFF;
		}

	}

	// Array for cipher text corresponding to the each round 
	uint8_t **roundcipher1 = malloc(sizeof(uint8_t *)*9);
	for (i = 0; i < 9; i++) {
		roundcipher1[i] = malloc(sizeof(uint8_t) * 16);
	}
	uint8_t **roundcipher2 = malloc(sizeof(uint8_t *)*9);
	for (i = 0; i < 9; i++) {
		roundcipher2[i] = malloc(sizeof(uint8_t) * 16);
	}

	// Choose random index to change
	srand((unsigned int)(time(NULL)+41*flag2));

	int shift_index = rand()%128;
	if (flag == 1){
		int index = shift_index/8;
		int bit = shift_index%8;
		plaintext2[index] ^= (1 << (7-bit));

	}

	uint8_t ciphertext[AES_BLOCK_SIZE];
	uint8_t ciphertext2[AES_BLOCK_SIZE];
	uint8_t decryptedtext[AES_BLOCK_SIZE];

	uint8_t roundkeys[AES_ROUND_KEY_SIZE];

	if (flag != 1){
		char wall[] = "------------------------------------------------------";
		if (flag2 == 0){
			fprintf(fp, " [a]%s%s\n\n  (i)\n", wall, wall);
		}else if (flag2 == 1){
			fprintf(fp, "\n\n [b]%s%s\n\n  (i)\n", wall, wall);
		}

		fprintf(fp, "      PT    = ");
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			fprintf(fp, "%02x ", plaintext[i]);
		}
		fprintf(fp, "\n\n");

		fprintf(fp, "     KEY    = ");
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			fprintf(fp, "%02x ", key[i]);
		}
		fprintf(fp, "\n\n");
	}
	// key scheduling
	aes_key_schedule_128(key, roundkeys);

	// encryption
	if (flag != 1){
		aes_encrypt_128(roundkeys, plaintext, ciphertext, flag, roundcipher1);
	}
	if (flag == 1){
		aes_encrypt_128(roundkeys, plaintext, ciphertext, flag, roundcipher1);
		aes_encrypt_128(roundkeys, plaintext2, ciphertext2, flag, roundcipher2);
	}
	if (flag != 1){
		fprintf(fp, "      CT    = ");
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			fprintf(fp, "%02x ", ciphertext[i]);
		}
		fprintf(fp, "\n\n");

		// decryption
		aes_decrypt_128(roundkeys, ciphertext, decryptedtext);
		if (flag != 1){
			fprintf(fp, "  Decrypted = ");
			for (i = 0; i < AES_BLOCK_SIZE; i++) {
				fprintf(fp, "%02x ", decryptedtext[i]);
			}
			fprintf(fp, "\n");
			for (i = 0; i < 9; i++) {
				free(roundcipher1[i]);
			}
			free(roundcipher1);
			for (i = 0; i < 9; i++) {
				free(roundcipher2[i]);
			}
			free(roundcipher2);
			return;
		}
	}

	// Case flag == 1 Generate string
	fprintf(fp, "\n\n  (ii)\n");
	int j;
	int distance = hamming(plaintext, plaintext2);
	fprintf(fp, "  Hamming distance when %dth bit is changed\n\n", shift_index+1);
	fprintf(fp, "  PT:  %03d   ", distance);
	for (j = 0; j < AES_BLOCK_SIZE; j++){
		fprintf(fp, "%02x ", plaintext[j]);
	}
	fprintf(fp, "    ");
	for (j = 0; j < AES_BLOCK_SIZE; j++){
		fprintf(fp, "%02x ", plaintext2[j]);
	}
	fprintf(fp, "\n\n");

	for (i = 0; i < 9 ; i++){
		distance = hamming(roundcipher1[i], roundcipher2[i]);
		fprintf(fp, "  R%d:  %03d   ", i+1, distance);
		for (j = 0; j < AES_BLOCK_SIZE; j++){
			fprintf(fp, "%02x ", roundcipher1[i][j]);
		}
		fprintf(fp, "    ");
		for (j = 0; j < AES_BLOCK_SIZE; j++){
			fprintf(fp, "%02x ", roundcipher2[i][j]);
		}
		fprintf(fp, "\n\n");
	}

	distance = hamming(ciphertext, ciphertext2);
	fprintf(fp, "  CT:  %03d   ", distance);
	for (j = 0; j < AES_BLOCK_SIZE; j++){
		fprintf(fp, "%02x ", ciphertext[j]);
	}
	fprintf(fp, "    ");
	for (j = 0; j < AES_BLOCK_SIZE; j++){
		fprintf(fp, "%02x ", ciphertext2[j]);
	}
	fprintf(fp, "\n");

	for (i = 0; i < 9; i++) {
		free(roundcipher1[i]);
	}
	free(roundcipher1);
	for (i = 0; i < 9; i++) {
		free(roundcipher2[i]);
	}
	free(roundcipher2);
}

int main(void){
	FILE *fp;
	fp = fopen("./output.txt", "wt");
	if (fp == NULL){
		printf("Error occured opening file\n");
		return -1;
	}
	fprintf(fp, "    < Result of AES-128 Encryption Avalanche Property test > \n\n\n");

	test(fp, 0, 0);
	test(fp, 1, 0);
	test(fp, 0, 1);
	test(fp, 1, 1);

	fprintf(fp, "\n\n  < End of Result >");

	fclose(fp);

	return 0;
}


