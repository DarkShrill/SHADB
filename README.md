# SHADB
Simple and funny application with SHA. In particular this application save the SHA value of the input file passed. Available SHA: SHA1 SHA224 SHA256 SHA384 SHA512

```
         #############################################
         ###                                       ###
         ###     SHADB DIGEST FILE ARCHIVATION     ###
         ###                                       ###
         ###           Version : 1.0               ###
         ###               created by Edoardo Papa ###
         #############################################


         ATTENZIONE : Sintassi non riconosciuta.
                       SINTASSI : 
 
 [--dbfile | -d <dbfile>] add [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtofile> 

 Dove:
   - [--dbfile | -d <dbfile>] è il file di output dove andranno salvati i file analizzati. ( Se omesso verranno salvati in shadb.out )
   - [SHA1|SHA224|SHA256|SHA384|SHA512] è la funzione SHA scelta per calcolare il digest. ( Se omesso verrà utilizzato SHA1)
   - <pathtofile> è il path in cui si trova il file da analizzare.

[--dbfile | -d <dbfile>] find [SHA1|SHA224|SHA256|SHA384|SHA512] <pathtofile> 

 Quest'ultimo è utilizzato per ricercare se un determinato file codificato con un determinato SHA è presente nel nostro archivio.
 

```
