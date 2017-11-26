/*--------------------------------------------------------------------*/
/* testkeycrypto.c                                                       */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keycrypto.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>  
#include <assert.h>
#include <stdio.h>

#define ASSURE(i) assure(i, __LINE__)
#define INTBUFLEN (sizeof(int) * 4 + 1)            
#define ARRBUFLEN (sizeof(unsigned char) * 8 + 1)

/* If !iSuccessful, print a message to stdout indicating that the
   test failed. */

static void assure(int iSuccessful, int iLineNum)
{
    if (! iSuccessful)
    {
        printf("Test at line %d failed.\n", iLineNum);
        fflush(stdout);
    }
}

static void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

static void phex(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < 4; i++)
        printf("%.2x", str[i]);
    printf("\n");
}

static void testBasics()
{
    unsigned char aucKey0[] = {0x00, 0x00, 0x00, 0x00};

    unsigned char aucKey1[] = {0x00, 0x00, 0x00, 0x01};  

    unsigned char aucKey2[] = {0x6d, 0x22, 0xa5, 0x1d};

    unsigned char aucKey3[] = {0x09, 0xf1, 0x73, 0xba};

    unsigned char aucInput0[] = {0x72, 0x3d, 0x38, 0xae};

    unsigned char aucInput1[] = {0xa5, 0x51, 0x0f, 0x58,
                                 0xda, 0x91, 0xcd, 0xc2,
                                 0x4b, 0x40, 0xd7, 0xff,
                                 0x00, 0xe0, 0x8b, 0x68};

    unsigned char aucInput2[] = {0x00, 0x00, 0x00, 0x05}; 

    unsigned char aucOutput00[] = {0x72, 0x3d, 0x38, 0xae};

    unsigned char aucOutput01[] = {0xa5, 0x51, 0x0f, 0x58,
                                   0xda, 0x91, 0xcd, 0xc2,
                                   0x4b, 0x40, 0xd7, 0xff,
                                   0x00, 0xe0, 0x8b, 0x68};

    unsigned char aucOutput10[] = {0x72, 0x3d, 0x38, 0xaf};

    unsigned char aucOutput11[] = {0xa5, 0x51, 0x0f, 0x59,
                                   0xda, 0x91, 0xcd, 0xc3,
                                   0x4b, 0x40, 0xd7, 0xfe,
                                   0x00, 0xe0, 0x8b, 0x69};

    unsigned char aucOutput20[] = {0x1f, 0x1f, 0x9d, 0xb3};

    unsigned char aucOutput21[] = {0xc8, 0x73, 0xaa, 0x45,
                                   0xb7, 0xb3, 0x68, 0xdf,
                                   0x26, 0x62, 0x72, 0xe2,
                                   0x6d, 0xc2, 0x2e, 0x75};

    unsigned char aucOutput30[] = {0x7b, 0xcc, 0x4b, 0x14};

    unsigned char aucOutput31[] = {0xac, 0xa0, 0x7c, 0xe2,
                                   0xd3, 0x60, 0xbe, 0x78,
                                   0x42, 0xb1, 0xa4, 0x45,
                                   0x09, 0x11, 0xf8, 0xd2};

    unsigned char aucOutput12[] = {0x00, 0x00, 0x00, 0x04};

    unsigned char aucBufferShort[4];
    unsigned char aucBufferLong[16];

    printf("------------------------------------------------------\n");
    printf("Testing XOR Encrypt and Decrypt.\n");
    printf("No output should appear here:\n");
    fflush(stdout);

    memset(aucBufferShort, 0, 4);
    memset(aucBufferLong, 0, 16);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey0);
    ASSURE(memcmp(aucBufferShort, aucOutput00, 4) == 0);

    xor_decrypt(aucOutput00, aucBufferShort, 4, aucKey0);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey0);
    ASSURE(memcmp(aucBufferLong, aucOutput01, 16) == 0);

    xor_decrypt(aucOutput01, aucBufferLong, 16, aucKey0);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey1);
    ASSURE(memcmp(aucBufferShort, aucOutput10, 4) == 0);

    xor_decrypt(aucOutput10, aucBufferShort, 4, aucKey1);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey1);
    ASSURE(memcmp(aucBufferLong, aucOutput11, 16) == 0);

    xor_decrypt(aucOutput11, aucBufferLong, 16, aucKey1);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey2);
    ASSURE(memcmp(aucBufferShort, aucOutput20, 4) == 0);

    xor_encrypt(aucOutput20, aucBufferShort, 4, aucKey2);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey2);
    ASSURE(memcmp(aucBufferLong, aucOutput21, 16) == 0);

    xor_decrypt(aucOutput21, aucBufferLong, 16, aucKey2);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey3);
    ASSURE(memcmp(aucBufferShort, aucOutput30, 4) == 0);

    xor_decrypt(aucOutput30, aucBufferShort, 4, aucKey3);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey3);
    ASSURE(memcmp(aucBufferLong, aucOutput31, 16) == 0);

    xor_decrypt(aucOutput31, aucBufferLong, 16, aucKey3);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_decrypt(aucInput2, aucBufferShort, 4, aucKey1);
    ASSURE(memcmp(aucBufferShort, aucOutput12, 4) == 0); 


}

static void testHash()
{

    char aucKeyID_0[] = "0";
    char aucKeyID_00[] = "00";
    char aucKeyID_000[] = "000";
    int i = 5;
    int j = 2147483647;
    int k = 5214748;
    unsigned char aucKey0[] = {0x01, 0x23, 0x45, 0x67};
    unsigned char aucKey1[] = {0x01, 0x23, 0x00, 0x67};

    int iter;
    char intBuf[INTBUFLEN];
    char ucBuf[ARRBUFLEN];
    unsigned char hash[32];
    SHA256_CTX ctx;

    printf("------------------------------------------------------\n");
    printf("Testing Hashing.\n");
    printf("Some 32 byte hash outputs should appear here:\n");
    fflush(stdout);

    sha256_init(&ctx);
    sha256_update(&ctx,aucKeyID_0,strlen(aucKeyID_0));
    sha256_update(&ctx,aucKeyID_00,strlen(aucKeyID_00));
    sha256_final(&ctx,hash);
    print_hash(hash);

    sha256_init(&ctx);
    sha256_update(&ctx,aucKeyID_000,strlen(aucKeyID_000));
    sha256_final(&ctx,hash);
    print_hash(hash);

    sha256_init(&ctx);
    intToString(i, intBuf);
    sha256_update(&ctx,intBuf,strlen(intBuf));
    intToString(j, intBuf);
    // printf("String: %s\n", intBuf);
    sha256_update(&ctx,intBuf,strlen(intBuf));
    sha256_final(&ctx,hash);
    print_hash(hash);

    sha256_init(&ctx);
    intToString(k, intBuf);
    // printf("String: %s\n", intBuf);
    sha256_update(&ctx,intBuf,strlen(intBuf));
    sha256_final(&ctx,hash);
    print_hash(hash);

    sha256_init(&ctx);
    arrToString(aucKey0, ucBuf);
    // printf("String: %s, %d\n", ucBuf, strlen(ucBuf));
    sha256_update(&ctx,ucBuf,strlen(ucBuf));
    sha256_final(&ctx,hash);
    print_hash(hash);
}

int main(void)
{
    testBasics();
    testHash();

    printf("------------------------------------------------------\n");
    printf("End of tests\n");
} 
