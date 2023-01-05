//
// Created by Edoardo Papa on 2019-09-12.
//

#include "rwfile.h"
#include "string.h"
#include <stdlib.h>
#include "general.h"
#include "manage_sha.h"


/**
 * Questa fuonzione permette di scrivere all'interno del file selezionato le informazioni da aggiungere al repository.
 * @param arg struttura contenente i parametri :
 *                                                  -    enum TYPE_OF_OPTION * type;                      < Tipo di istruzione da eseguire
 *                                                  -    enum TYPE_SHA       * sha;                       < Tipo di SHA da eseguire
 *                                                  -    char                * output_file;               < PATH del file di output dove andare a prendere e a cercare i dati
 *                                                  -    char                * analize_file;              < PATH del file da analizzare
 *                                                  -    char                * type_command;
 * @param digest DIGEST da aggiungere
 * @param len lunghezza del DIGEST
 */
void write_new_element_to_file(struct digit_arguments arg,char * digest, unsigned long len)
{
    FILE *file = fopen(arg.output_file, "a+");      // Apro il file in append mode

    for(unsigned long i = 0; i < strlen(arg.analize_file);i++)
    {
        fprintf(file,"%c",arg.analize_file[i]);
    }

    fprintf(file,"\n");

    char * string_of_sha = get_string_of_sha(arg.sha);

    fprintf(file,"%s\n",string_of_sha);

    for(unsigned long i = 0; i < len;i++)
    {
        if((digest[i]&0xFF)<= 0xF)
        {
            fprintf(file,"0%x",digest[i]&0xFF);
        }
        else
        {
            fprintf(file,"%x",digest[i]&0xFF);
        }

    }
    fprintf(file,"\n");

    fclose(file);

}


/**
 * Leggo tutto il file contenuto al PATH passato come parametro formale e restituisco il puntatore di dove sono contenuti i dati del file.
 * @param path PATH del file
 * @return puntatore contenente i dati del file
 */
char * ReadFile(char *path) {

    char read;
    unsigned short counter_charatter = 0;
    FILE *file;



    file = fopen(path, "r+");          // Apro il file in lettura

    if (file == NULL)
    {
        printf("\nFILE NON PRESENTE\n");
        fclose(file);
        return 0;

    }

    while ((read = fgetc(file)) != EOF) {   // Leggo fino alla file del file (EOF)
        counter_charatter++;
    }

    fseek(file,0,0);

    char *data=  malloc(sizeof(char*) * counter_charatter);

    if(data == NULL)
    {
        printf("Memoria esaurita\n");
        fclose(file);
        exit(1);
    }

    while ((read = fgetc(file)) != EOF) {   // Leggo fino alla file del file (EOF)
        *data = read;
        data++;
    }
    *data = '\0';

    fclose(file);

    data -= counter_charatter;

    return data;



//    char data[counter_charatter];// = malloc((sizeof(char) * counter_charatter) );
//
//    if(data == NULL)
//    {
//        printf("Memoria esaurita\n");
//        fclose(file);
//        exit(1);
//    }
//    int i = 0;
//    while ((read = fgetc(file)) != EOF) {   // Leggo fino alla file del file (EOF)
////        *data = read;
////        data++;
//        data[i] = read;
//        i++;
//    }
//    //*data = '\0';
//    //data[i] = '\0';
//
//    fclose(file);
//
//    //data -= counter_charatter;
//
//    return &data[0];
}



/************************************************       PER TEST       ************************************************/



void test_all_function_from__RWFILE_H(char * path_to_analize, char* path)
{

    /**********************************     WRITE NEW ELEMENT TO FILE     **********************************/

    printf("Hai appena eseguito      write_new_element_to_file()&\n"
           "                        ReadFile functions and the test is: ");

struct digit_arguments arg;

    path_to_analize[strlen(path_to_analize) - 24] = '\0';
    strcat(&path_to_analize[0],"analize_file_for_test.in");

    arg.analize_file   = malloc(sizeof(arg.analize_file));
    strcpy(arg.analize_file,path_to_analize);

    path[strlen(path) - 24] = '\0';
    strcat(&path[0],"shadb_for_test.out");


    arg.sha           = SHA1;
    arg.output_file  = path;

    write_new_element_to_file(arg,"12345678912345678912",20);


    /**********************************     READ FILE     **********************************/

    char * ret = strstr(ReadFile(path),"3132333435363738393132333435363738393132");

    ret[41] = '\0';

    if(strcmp(ret,"3132333435363738393132333435363738393132\n") != 0)
    {
        printf("                                       failed\n");
    }
    printf("                                       passed\n");


}