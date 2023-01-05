//
// Created by Edoardo Papa on 2019-09-05.
//

#include "common.h"

/**
 * Manipolo i dati contenuti all'iterno dell'array passato @data nella posizione @number e mi estrapolo il valore
 * @param data array di ingresso
 * @param number indice dell'array
 * @return
 */
unsigned long get_manipulate_integer_big_endian(unsigned char data[64],unsigned short number)
{
    unsigned long temp = 0;

    temp |= ((unsigned long) (data[number])     << 24 );
    temp |= ((unsigned long) (data[number + 1]) << 16 );
    temp |= ((unsigned long) (data[number + 2]) <<  8 );
    temp |= ((unsigned long) (data[number + 3])       );

    return temp;
}

/**
 * Manipolo i dati e li inserisco all'iterno dell'array passato @data nella posizione @index
 * @param data array di ingresso
 * @param value valore da inserire
 * @param index indice dell'array
 * @return
 */
void put_manipulate_integer_big_endian(unsigned char * data, unsigned long value ,unsigned long index)
{
    data[(index)    ] = (unsigned char) ( (value) >> 24 );
    data[(index) + 1] = (unsigned char) ( (value) >> 16 );
    data[(index) + 2] = (unsigned char) ( (value) >>  8 );
    data[(index) + 3] = (unsigned char) ( (value)       );
}


/**
 *      64BIT
 *
 * Manipolo i dati contenuti all'iterno dell'array passato @data nella posizione @number e mi estrapolo il valore
 * @param data array di ingresso
 * @param number indice dell'array
 * @return
 */
unsigned long long get_manipulate_64_integer_big_endian(unsigned char data[128],unsigned short number)
{
    unsigned long long temp = 0;

    temp |= ((unsigned long long ) (data[number])     << 56 );
    temp |= ((unsigned long long) (data[number + 1]) << 48 );
    temp |= ((unsigned long long) (data[number + 2]) << 40 );
    temp |= ((unsigned long long) (data[number + 3]) << 32 );
    temp |= ((unsigned long long) (data[number + 4]) << 24 );
    temp |= ((unsigned long long) (data[number + 5]) << 16 );
    temp |= ((unsigned long long) (data[number + 6]) <<  8 );
    temp |= ((unsigned long long) (data[number + 7])       );

    return temp;
}


/**
 *     64BIT
 *
 * Manipolo i dati contenuti e li inserisco all'iterno dell'array passato @data nella posizione @index
 * @param data array di ingresso
 * @param value valore da inserire
 * @param index indice dell'array
 * @return
 */
void put_manipulate_64_integer_big_endian(unsigned char * data, unsigned long long value ,unsigned long index)
{
    data[(index)    ] = (unsigned char) ( (value) >> 56 );
    data[(index) + 1] = (unsigned char) ( (value) >> 48 );
    data[(index) + 2] = (unsigned char) ( (value) >> 40 );
    data[(index) + 3] = (unsigned char) ( (value) >> 32 );
    data[(index) + 4] = (unsigned char) ( (value) >> 24 );
    data[(index) + 5] = (unsigned char) ( (value) >> 16 );
    data[(index) + 6] = (unsigned char) ( (value) >>  8 );
    data[(index) + 7] = (unsigned char) ( (value)       );
}



/**
 * Eseguo una rotazione verso sinistra
 * @param data valore
 * @param num numero shift
 * @return risultato
 */
unsigned long rolLeft(unsigned long data, unsigned char num)
{
    unsigned long temp = 0;

    temp = (data << num) | ((data & 0xFFFFFFFF) >> (32 - num));

    return temp;
}

/**
 * Eseguo una rotazione verso destra
 * @param data valore
 * @param num numero shift
 * @return risultato
 */
unsigned long rolRight(unsigned long data, unsigned char num)
{
    unsigned long temp = 0;

    temp = (((data & 0xFFFFFFFF) >> num) | (data << (32 - num)));

    return temp;
}

/**
 *      64BIT
 *
 * Eseguo una rotazione verso destra
 * @param data valore
 * @param num numero shift
 * @return risultato
 */
unsigned long long rolRight_64bit(unsigned long long data, unsigned char num)
{
    unsigned long temp = 0;

    temp = (((data ) >> num) | (data << (64 - num)));

    return temp;
}