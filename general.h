//
// Created by Edoardo Papa on 2019-09-07.
//

#ifndef SHADBPROJECT_GENERAL_H
#define SHADBPROJECT_GENERAL_H



enum TYPE_SHA {
    SHA1    = 'SHA1\n',
    SHA224  = 'SHA224\n',
    SHA256  = 'SHA256\n',
    SHA384  = 'SHA384\n',
    SHA512  = 'SHA512\n',
};


enum TYPE_OF_OPTION{
    ADD   = 23,
    FIND  = 86,
    ERROR = 404
};


struct digit_arguments {
    enum TYPE_OF_OPTION   type;                     /* < Tipo di istruzione da eseguire  */
    enum TYPE_SHA         sha;                      /* < Tipo di SHA da eseguire  */
    char                * output_file;              /* < PATH del file di output dove andare a prendere e a cercare i dati */
    char                * analize_file;             /* < PATH del file da analizzare */
    char                * type_command;             /* < Tipo di comando --> puo essere --<path> oppure -d <path>  */
};

typedef struct FILE_OUT_INFO {
    char                    * absolute_path;        /* < PATH assoluto del file analizzato  */
    enum TYPE_SHA             sha;                  /* < Tipo di SHA eseguito  */
    char                    * digest;               /* < Digest associato al file analizzato  */
    struct FILE_OUT_INFO    * next_element;         /* < Puntatore alla successiva struttura */
} FILE_OUT_INFO;


static struct {
    const char *s;                                  /* < "Stringa" dell'SHA  */
    enum TYPE_SHA    sha;                           /* < Tipo di SHA  */
}map[5] = {
        { "SHA1", SHA1 },
        { "SHA224", SHA224 },
        { "SHA256", SHA256 },
        { "SHA384", SHA384 },
        { "SHA512", SHA512 },
};


FILE_OUT_INFO analizeFile(char * path);
unsigned long get_len_of_data(const char * data);
void exist_file(char * path);

/************************************************       PER TEST       ************************************************/

void test_all_function_from__GENERAL_H(char * path);

#endif //SHADBPROJECT_GENERAL_H
