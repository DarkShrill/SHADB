//
// Created by Edoardo Papa on 2019-09-11.
//

#include <stdlib.h>
#include "manager.h"
#include "manage_sha.h"
#include "stdio.h"
#include "string.h"
#include "rwfile.h"

char * helper = "[--dbfile | -d <dbfile>] add [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtofile> \n\n Dove:\n   - [--dbfile | -d <dbfile>] è il file di output dove andranno salvati \
i file analizzati. ( Se omesso verranno salvati in shadb.out )\n   - [SHA1|SHA224|SHA256|SHA384|SHA512] è la funzione SHA scelta per calcolare il digest. ( Se omesso \
verrà utilizzato SHA1)\n   - <pathtofile> è il path in cui si trova il file da analizzare.\n\n[--dbfile | -d <dbfile>] find [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtofile> \n\n Quest'ultimo \
è utilizzato per ricercare se un determinato file codificato con un determinato SHA è presente nel nostro archivio.\n";


/**
 * Questa funzione permette di eseguire, a seconda del comando ricevuto, una determinata operazione.
 * @param type tipo di comando.
 * @param arg struttura contenente i parametri :
 *                                                  -    enum TYPE_OF_OPTION * type;                      < Tipo di istruzione da eseguire
 *                                                  -    enum TYPE_SHA       * sha;                       < Tipo di SHA da eseguire
 *                                                  -    char                * output_file;               < PATH del file di output dove andare a prendere e a cercare i dati
 *                                                  -    char                * analize_file;              < PATH del file da analizzare
 *                                                  -    char                * type_command;
*/
void manage_command_received(enum TYPE_OF_OPTION type, struct digit_arguments * arg)
{

    switch(type)
    {
        case ADD :
        {
            add_command(arg);
            break;
        }
        case FIND :
        {
            find_command(arg);
            break;
        }
        case ERROR:
        default:
        {
            fprintf(stderr,"         ATTENZIONE : Sintassi non riconosciuta.\n                       SINTASSI : \n \n %s \n",helper);
            exit(404);
        }
    }
}

/**
 * Questa funzione permette di eseguire il comando @FIND
 * @param arg struttura contenente i parametri :
 *                                                  -    enum TYPE_OF_OPTION * type;                      < Tipo di istruzione da eseguire
 *                                                  -    enum TYPE_SHA       * sha;                       < Tipo di SHA da eseguire
 *                                                  -    char                * output_file;               < PATH del file di output dove andare a prendere e a cercare i dati
 *                                                  -    char                * analize_file;              < PATH del file da analizzare
 *                                                  -    char                * type_command;
*/
void find_command(struct digit_arguments * arg)
{

unsigned char needBuffer_size = 0;

    needBuffer_size = get_SHA_needBuffer_size(arg->sha);

    char * out_sha;

    //out_sha = (char *)malloc(sizeof(char *)*needBuffer_size);

    out_sha = calculate_SHA(arg->analize_file,arg->sha,needBuffer_size);


    char * temp_arr = malloc(needBuffer_size);

    for(int i = 0; i < needBuffer_size; i++) {
        temp_arr[i] =*out_sha;
        out_sha++;
    }

    if(find_digest(arg->output_file,temp_arr))
    {
        // NON HO TROVATO NESSUNA INFORMAZIONE UGUALE
        fprintf(stderr, "         Il file NON è presente nell'archivio! \n\n");
        //free(out_sha);
        exit(505);
    }
    else
    {

        printf("         Il file è già presente nell'archivio. \n\n");
        printf("         PATH    : %s \n",arg->analize_file);
        printf("         SHA     : %s \n",get_string_of_sha(arg->sha));
        printf("         DIGEST  : ");get_string_of_digest(temp_arr,needBuffer_size);
        //free(out_sha);
        exit(505);
    }

    //free(out_sha);
}

/**
 * Questa funzione permette scoprire se è presente o meno un determinato DIGEST all'interno del file selezionato
 * @param path PATH del file in cui bisogna trovare il DIGEST
 * @param digest DIGEST da trovare
 * @return 0 se ho trovato il DIGEST all'interno del file, altrimenti 1.
 */
unsigned char find_digest(char * path,char * digest) {

    FILE_OUT_INFO list = analizeFile(path);
    FILE_OUT_INFO *current = &list;
    size_t len = strlen(digest);
    if (list.digest == NULL)
    {
        //printf("LISTA VUOTA\n");
        return 1;
    }

    while (is_same_digest(current,digest,len) == 1)
    {
        // Se sono arrivato all'ultimo elemento e non ho trovato nulla, ritorno 1
        if (current->next_element == NULL)
        {
            return 1;
        }
        current = current->next_element;
    }

    return 0;
}

/**
 * Questa funzione permette di eseguire il comando @ADD
 * @param arg struttura contenente i parametri :
 *                                                  -    enum TYPE_OF_OPTION * type;                      < Tipo di istruzione da eseguire
 *                                                  -    enum TYPE_SHA       * sha;                       < Tipo di SHA da eseguire
 *                                                  -    char                * output_file;               < PATH del file di output dove andare a prendere e a cercare i dati
 *                                                  -    char                * analize_file;              < PATH del file da analizzare
 *                                                  -    char                * type_command;
*/
void add_command(struct digit_arguments * arg)
{
    unsigned char needBuffer_size = 0;

    needBuffer_size = get_SHA_needBuffer_size(arg->sha);

    char * out_sha;

    //out_sha = (char *)malloc(sizeof(char *)*needBuffer_size);

    out_sha = calculate_SHA(arg->analize_file,arg->sha,needBuffer_size);

    char * temp_arr = malloc(sizeof(char *) * needBuffer_size);

    for(int i = 0; i < needBuffer_size; i++) {
        temp_arr[i] =*out_sha;
        out_sha++;
    }
    temp_arr[needBuffer_size] = '\0';

    if(find_digest(arg->output_file,temp_arr))
    {
        // NON HO TROVATO NESSUNA INFORMAZIONE UGUALE, QUINDI AGGIUNGO IN NUOVO SHA
        write_new_element_to_file(*arg,temp_arr,needBuffer_size);
    }
    else
    {
        fprintf(stderr, "         ATTENZIONE! Il file è già presente nell'archivio. \n\n");
        exit(505);
    }
}
