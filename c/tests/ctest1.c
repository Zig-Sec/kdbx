#include "kdbx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) 
{
    char* path = "c/tests/TestDb.kdbx";
    char* pw = "test123";
    
    int ret = 0;
    void* database;
    
    // First we open the database
    if ((ret = kdbx_open_with_password(&database, path, strlen(path), pw, strlen(pw))) != 0) {
        printf("error opening kdbx file (%d)\n", ret);
        exit(1);
    }
    
    kdbx_close(database);
    return 0;
}
