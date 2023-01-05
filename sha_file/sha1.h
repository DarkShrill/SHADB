//
// Created by Edoardo Papa on 2019-09-02.
//

#ifndef SHADBPROJECT_SHA1_H
#define SHADBPROJECT_SHA1_H


static const unsigned char sha1_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define operation_1(x,y,z) (z ^ (x & (y ^ z)))
#define operation_2(x,y,z) (x ^ y ^ z)
#define operation_3(x,y,z) ((x & y) | (z & (x | y)))
#define operation_4(x,y,z) (x ^ y ^ z)



typedef struct
{
    unsigned long total[2];          /* < numero di byte processati  */
    unsigned long state[5];          /* < stato del digest  */
    unsigned char buffer[64];        /* < blocco di dati in elaborazione */
}sha1_context;


void sha1_init( sha1_context * context );
void sha1_free( sha1_context * context );
void sha1_starts( sha1_context * context );
void sha1_update( sha1_context * context, unsigned char *input, size_t ilen );
void sha1_finish( sha1_context * context, char output[20] );
void sha1_process( sha1_context *ctx, unsigned char data[64] );
void sha1_clear( sha1_context * context, size_t n );
void sha1(unsigned char * input, size_t ilen, char output[20] );


/************************************************       PER TEST       ************************************************/


unsigned char sha_self_test(unsigned char index);

#endif //SHADBPROJECT_SHA1_H
