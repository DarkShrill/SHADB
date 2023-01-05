//
// Created by Edoardo Papa on 2019-09-07.
//

#ifndef SHADBPROJECT_SHA_384_H
#define SHADBPROJECT_SHA_384_H

#include <stddef.h>
#include "common.h"


static const unsigned char sha384_padding[128] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define UL64(data) ((unsigned long long) data )

#define operation_384_1(x) (rolRight_64bit(x, 1) ^ rolRight_64bit(x,8) ^  ((x) >> 7))
#define operation_384_2(x) (rolRight_64bit(x,19) ^ rolRight_64bit(x,61) ^ ((x) >> 6))

#define operation_384_3(x) (rolRight_64bit(x, 28) ^ rolRight_64bit(x,34) ^ rolRight_64bit(x,39))
#define operation_384_4(x) (rolRight_64bit(x, 14) ^ rolRight_64bit(x,18) ^ rolRight_64bit(x,41))

#define operation_384_5(x,y,z) ((x & y) | (z & (x | y)))
#define operation_384_6(x,y,z) (z ^ (x & (y ^ z)))


typedef struct
{
    unsigned long long total[2];          /* < numero di byte processati  */
    unsigned long long state[8];          /* < stato del digest  */
    unsigned char buffer[128];            /* < blocco di dati in elaborazione */
}sha384_context;


void sha384_init( sha384_context * context );
void sha384_free( sha384_context * context );
void sha384_starts( sha384_context * context );
void sha384_update( sha384_context * context, const unsigned char *input,size_t ilen );
void sha384_finish( sha384_context * context, char output[64] );
void sha384(unsigned char *input, size_t ilen,char output[64] );
void sha384_process( sha384_context *ctx, const unsigned char data[128] );




/************************************************       PER TEST       ************************************************/



unsigned char sha384_self_test(unsigned char index);



#endif //SHADBPROJECT_SHA_384_H
