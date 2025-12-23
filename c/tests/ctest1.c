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
    void* group;
    void* entry;
    
    // First we open the database
    if ((ret = kdbx_open_with_password(&database, path, strlen(path), pw, strlen(pw))) != 0) {
        printf("error opening kdbx file (%d)\n", ret);
        exit(1);
    }
    
    // Groups (starting from the 'Root') can be referenced by seperating nested groups with a '/'.
    //
    // To get the root group use: '/'
    // To get the child group 'Test1' of the Root use '/Test1'.
    if ((ret = kdbx_db_get_group(&group, database, "/Test1", 6)) != 0) {
        printf("error accessing the group '%s' (%d)\n", "/Test1", ret);
        exit(1);
    }
    
    // Given a group, one can access its entries.
    if ((ret = kdbx_group_get_entry_by_key(&entry, group, "Title", strlen("Title"), "Test Entry 2", strlen("Test Entry 2"))) != 0) {
        printf("error accessing the entry '%s' (%d)\n", "Test Entry 2", ret);
        exit(1);
    }

    // You can access a specific key-value from an entry using the following function:
    uint8_t* value = kdbx_entry_get_value(entry, "Title", strlen("Title"));
    if (!value) { // Make sure you check for null!
        printf("error accessing the title of '%s'\n", "Test Entry 2");
        exit(1);
    }
    printf("Title = '%s'\n", value);
    free(value);
    value = NULL;

    value = kdbx_entry_get_value(entry, "Password", strlen("Password"));
    if (!value) { // Make sure you check for null!
        printf("error accessing the password of '%s'\n", "Test Entry 2");
        exit(1);
    }
    printf("Password = '%s'\n", value);
    free(value);
    value = NULL;
    
    kdbx_close(database);
    return 0;
}
