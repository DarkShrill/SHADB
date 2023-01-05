//
// Created by Edoardo Papa on 2019-09-05.
//

#ifndef SHADBPROJECT_SHA_224_H
#define SHADBPROJECT_SHA_224_H

#include "stdio.h"

#define operation_224_1(x) (rolRight(x, 7) ^ rolRight(x,18) ^  ((x & 0xFFFFFFFF) >> 3))
#define operation_224_2(x) (rolRight(x,17) ^ rolRight(x,19) ^  ((x & 0xFFFFFFFF) >> 10))

#define operation_224_3(x) (rolRight(x, 2) ^ rolRight(x,13) ^ rolRight(x,22))
#define operation_224_4(x) (rolRight(x, 6) ^ rolRight(x,11) ^ rolRight(x,25))

#define operation_224_5(x,y,z) ((x & y) | (z & (x | y)))
#define operation_224_6(x,y,z) (z ^ (x & (y ^ z)))



static const unsigned char sha224_padding[64] =
{
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


typedef struct
{
    unsigned long total[2];          /* < numero di byte processati  */
    unsigned long state[8];          /* < stato del digest  */
    unsigned char buffer[64];        /* < blocco di dati in elaborazione */
}sha224_context;

void sha224_clear( sha224_context * context, size_t n );
void sha224_init( sha224_context *ctx );
void sha224_free( sha224_context *ctx );
void sha224_starts( sha224_context *ctx);
void sha224_update( sha224_context *ctx, const unsigned char *input,size_t ilen );
void sha224_finish( sha224_context *ctx, char output[28] );
void sha224_process( sha224_context *ctx, const unsigned char data[64] );
void sha224( unsigned char *input, size_t ilen,char output[28]);


/************************************************       PER TEST       ************************************************/

unsigned char sha224_self_test(unsigned char index);



#endif //SHADBPROJECT_SHA_224_H
