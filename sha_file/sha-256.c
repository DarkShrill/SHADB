//
// Created by Edoardo Papa on 2019-09-05.
//

#include "sha-256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"


#define transform_from_sixteen_to_sixtyfour(t)               \
(                                                            \
    W[t] = operation_256_2(W[t -  2]) + W[t -  7] +          \
           operation_256_1(W[t - 15]) + W[t - 16]            \
)

static const unsigned long K[] =
{
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};


/**
 * Inseirisco all'interno della struttura tutti 0x00
 * @param context struttura SHA256
 * @param n grandezza del buffer.
 */
void sha256_clear( sha256_context * context, size_t n )
{
    memset(context,0x00,n);
}

/**
 * Inserisco all'interno della struttura tutti 0x00
 * @param context struttura dell'SHA256
 */
void sha256_init( sha256_context * context )
{
    memset( context , 0x00 , sizeof( sha256_context ) );
}

/**
 * Verifico che la struttura non sia nulla e in caso negativo, inserisco al
 *  suo inteno tutti 0x00
 * @param context struttura dell'SHA256
 */
void sha256_free( sha256_context * context )
{
    if( context  == NULL )
        return;

    sha256_clear( context , sizeof( sha256_context ) );
}


/**
 * SetUp del SHA256
 * @param context struttura dell'SHA256
 */
void sha256_starts( sha256_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    /* SHA-256 */
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}


/**
 * Calcolo dell' SHA256
 * @param context struttura dell' SHA256
 * @param data blocco di dati in elaborazione
 */
void sha256_process( sha256_context *ctx, unsigned char data[64] )
{
unsigned long temp1,temp2,W[64];
unsigned long A[8];
unsigned char i;

    for( i = 0; i < 8; i++ )
        A[i] = ctx->state[i];

    W[0] = get_manipulate_integer_big_endian(data,  0);
    W[1] = get_manipulate_integer_big_endian(data,  4);
    W[2] = get_manipulate_integer_big_endian(data,  8);
    W[3] = get_manipulate_integer_big_endian(data,  12);
    W[4] = get_manipulate_integer_big_endian(data,  16);
    W[5] = get_manipulate_integer_big_endian(data,  20);
    W[6] = get_manipulate_integer_big_endian(data,  24);
    W[7] = get_manipulate_integer_big_endian(data,  28);
    W[8] = get_manipulate_integer_big_endian(data,  32);
    W[9] = get_manipulate_integer_big_endian(data,  36);
    W[10] = get_manipulate_integer_big_endian(data, 40);
    W[11] = get_manipulate_integer_big_endian(data, 44);
    W[12] = get_manipulate_integer_big_endian(data, 48);
    W[13] = get_manipulate_integer_big_endian(data, 52);
    W[14] = get_manipulate_integer_big_endian(data, 56);
    W[15] = get_manipulate_integer_big_endian(data, 60);

    for( i = 0; i < 16; i += 8 )
    {

        temp1 = A[7] + operation_256_4(A[4]) + operation_256_6(A[4],A[5],A[6]) + K[i+0] + W[i+0];
        temp2 = operation_256_3(A[0]) + operation_256_5(A[0],A[1],A[2]);
        A[3] += temp1;
        A[7] = temp1 + temp2;

        temp1 = A[6] + operation_256_4(A[3]) + operation_256_6(A[3],A[4],A[5]) + K[i+1] + W[i+1];
        temp2 = operation_256_3(A[7]) + operation_256_5(A[7],A[0],A[1]);
        A[2] += temp1;
        A[6] = temp1 + temp2;

        temp1 = A[5] + operation_256_4(A[2]) + operation_256_6(A[2],A[3],A[4]) + K[i+2] + W[i+2];
        temp2 = operation_256_3(A[6]) + operation_256_5(A[6],A[7],A[0]);
        A[1] += temp1;
        A[5] = temp1 + temp2;

        temp1 = A[4] + operation_256_4(A[1]) + operation_256_6(A[1],A[2],A[3]) + K[i+3] + W[i+3];
        temp2 = operation_256_3(A[5]) + operation_256_5(A[5],A[6],A[7]);
        A[0] += temp1;
        A[4] = temp1 + temp2;

        temp1 = A[3] + operation_256_4(A[0]) + operation_256_6(A[0],A[1],A[2]) + K[i+4] + W[i+4];
        temp2 = operation_256_3(A[4]) + operation_256_5(A[4],A[5],A[6]);
        A[7] += temp1;
        A[3] = temp1 + temp2;

        temp1 = A[2] + operation_256_4(A[7]) + operation_256_6(A[7],A[0],A[1]) + K[i+5] + W[i+5];
        temp2 = operation_256_3(A[3]) + operation_256_5(A[3],A[4],A[5]);
        A[6] += temp1;
        A[2] = temp1 + temp2;

        temp1 = A[1] + operation_256_4(A[6]) + operation_256_6(A[6],A[7],A[0]) + K[i+6] + W[i+6];
        temp2 = operation_256_3(A[2]) + operation_256_5(A[2],A[3],A[4]);
        A[5] += temp1;
        A[1] = temp1 + temp2;

        temp1 = A[0] + operation_256_4(A[5]) + operation_256_6(A[5],A[6],A[7]) + K[i+7] + W[i+7];
        temp2 = operation_256_3(A[1]) + operation_256_5(A[1],A[2],A[3]);
        A[4] += temp1;
        A[0] = temp1 + temp2;


    }


    for( i = 16; i < 64; i += 8 )
    {


        temp1 = A[7] + operation_256_4(A[4]) + operation_256_6(A[4],A[5],A[6]) + K[i+0] + transform_from_sixteen_to_sixtyfour(i+0);
        temp2 = operation_256_3(A[0]) + operation_256_5(A[0],A[1],A[2]);
        A[3] += temp1;
        A[7] = temp1 + temp2;

        temp1 = A[6] + operation_256_4(A[3]) + operation_256_6(A[3],A[4],A[5]) + K[i+1] + transform_from_sixteen_to_sixtyfour(i+1);
        temp2 = operation_256_3(A[7]) + operation_256_5(A[7],A[0],A[1]);
        A[2] += temp1;
        A[6] = temp1 + temp2;

        temp1 = A[5] + operation_256_4(A[2]) + operation_256_6(A[2],A[3],A[4]) + K[i+2] + transform_from_sixteen_to_sixtyfour(i+2);
        temp2 = operation_256_3(A[6]) + operation_256_5(A[6],A[7],A[0]);
        A[1] += temp1;
        A[5] = temp1 + temp2;

        temp1 = A[4] + operation_256_4(A[1]) + operation_256_6(A[1],A[2],A[3]) + K[i+3] + transform_from_sixteen_to_sixtyfour(i+3);
        temp2 = operation_256_3(A[5]) + operation_256_5(A[5],A[6],A[7]);
        A[0] += temp1;
        A[4] = temp1 + temp2;

        temp1 = A[3] + operation_256_4(A[0]) + operation_256_6(A[0],A[1],A[2]) + K[i+4] + transform_from_sixteen_to_sixtyfour(i+4);
        temp2 = operation_256_3(A[4]) + operation_256_5(A[4],A[5],A[6]);
        A[7] += temp1;
        A[3] = temp1 + temp2;

        temp1 = A[2] + operation_256_4(A[7]) + operation_256_6(A[7],A[0],A[1]) + K[i+5] + transform_from_sixteen_to_sixtyfour(i+5);
        temp2 = operation_256_3(A[3]) + operation_256_5(A[3],A[4],A[5]);
        A[6] += temp1;
        A[2] = temp1 + temp2;

        temp1 = A[1] + operation_256_4(A[6]) + operation_256_6(A[6],A[7],A[0]) + K[i+6] + transform_from_sixteen_to_sixtyfour(i+6);
        temp2 = operation_256_3(A[2]) + operation_256_5(A[2],A[3],A[4]);
        A[5] += temp1;
        A[1] = temp1 + temp2;

        temp1 = A[0] + operation_256_4(A[5]) + operation_256_6(A[5],A[6],A[7]) + K[i+7] + transform_from_sixteen_to_sixtyfour(i+7);
        temp2 = operation_256_3(A[1]) + operation_256_5(A[1],A[2],A[3]);
        A[4] += temp1;
        A[0] = temp1 + temp2;

    }

    ctx->state[0] = A[0] + ctx->state[0];
    ctx->state[1] = A[1] + ctx->state[1];
    ctx->state[2] = A[2] + ctx->state[2];
    ctx->state[3] = A[3] + ctx->state[3];
    ctx->state[4] = A[4] + ctx->state[4];
    ctx->state[5] = A[5] + ctx->state[5];
    ctx->state[6] = A[6] + ctx->state[6];
    ctx->state[7] = (A[7] + ctx->state[7]);

}

/**
 * Calcolo dell' SHA256
 * @param context struttura dell'SHA256
 * @param input buffer dati
 * @param ilen lunghezza del buffer
 */
void sha256_update( sha256_context *ctx, unsigned char *input,size_t ilen )
{
size_t fill;
unsigned long left;

    if( ilen == 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy((ctx->buffer + left), input, fill );
        sha256_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sha256_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
        memcpy((ctx->buffer + left), input, ilen );
}


/**
 * Calcolo finale del digest
 * @param context struttura dell'SHA256
 * @param output result
 */
void sha256_finish( sha256_context *ctx, char output[32] )
{
unsigned long last, padn;
unsigned long high, low;
unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    put_manipulate_integer_big_endian(msglen, high,  0 );
    put_manipulate_integer_big_endian(msglen, low,   4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha256_update( ctx, sha256_padding, padn );
    sha256_update( ctx, msglen, 8 );

    put_manipulate_integer_big_endian(output,ctx->state[0],  0 );
    put_manipulate_integer_big_endian(output,ctx->state[1],  4 );
    put_manipulate_integer_big_endian(output,ctx->state[2],  8 );
    put_manipulate_integer_big_endian(output,ctx->state[3],  12);
    put_manipulate_integer_big_endian(output,ctx->state[4],  16);
    put_manipulate_integer_big_endian(output,ctx->state[5],  20);
    put_manipulate_integer_big_endian(output,ctx->state[6],  24);
    put_manipulate_integer_big_endian(output,ctx->state[7],  28);



}

/**
 * Funzione generale per calcolare l'SHA256
 * @param input da decodificare
 * @param ilen lunghezza dell'input
 * @param output digest di uscita
 */
void sha256( unsigned char *input, size_t ilen,char output[32])
{
    sha256_context ctx;

    sha256_init( &ctx );
    sha256_starts( &ctx);
    sha256_update( &ctx, input, ilen );
    sha256_finish( &ctx, output );
    sha256_free( &ctx );
}



/************************************************       PER TEST       ************************************************/



static const unsigned char sha256_test_buf[2][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
};

static const int sha256_test_buflen[2] =
{
    3, 56
};

static const unsigned char sha256_test_sum[2][32] =
{
    { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
      0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
      0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
      0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD },
    { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
      0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
      0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
      0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 }
};



unsigned char sha256_self_test(unsigned char index)
{

unsigned char value_to_return = -1;
unsigned char sha256sum[32];
sha256_context context;


    sha256_init(&context);

    printf("Hai appena eseguito      SHA-256 test #%d: ", index);

    sha256_starts(&context);

    sha256_update(&context, sha256_test_buf[index], sha256_test_buflen[index]);

    sha256_finish(&context, sha256sum);


    if (memcmp(sha256sum, sha256_test_sum[index], 32) != 0)
    {
        // Non sono uguali, quindi qualcosa è andato storto.
        printf("failed\n");
        value_to_return = 0;
        goto END;
    }

    value_to_return = 1;

    printf("passed\n");

END:
    sha256_free( &context );

    return value_to_return;
}
