#include "kdbx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) 
{
    char* path = "testdb.kdbx";
    char* pw = "test123";

    void* database;

    if (kdbx_open_with_password(&database, path, strlen(path), pw, strlen(pw)) != 0) {
        puts("error opening kdbx file");
        exit(1);
    }
    
    kdbx_close(database);
    return 0;
}
