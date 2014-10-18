/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

/**
    CONSTANTS
*/
enum {DEBUG=1};

/**
    Declares an array struct
*/
typedef struct {
    char* array;
    size_t used;
    size_t size;
}charArr;

/**
    Declares the function headers
*/
void initArr(charArr* arr, size_t startSize);
void addArr(charArr* arr, char item);
void catArr(charArr* arr, char* items, int arrLen);
void freeArr(charArr* arr);
void resetArr(charArr* arr);

void error(const char *msg);



/**
    Main file
*/
int main(int argc, char *argv[])
{
    /**
        Declare variables
    */
    //Server socket
    int serverSock;
    //client socket
    int clientSock;
    //port number
    int portNr;
    //general purpose return value buffer
    int rval;
    // for counter
    int i;
    //Char buffer to read file
    int fc;
    

    //optval for setsockopt
    int optval;
    
    //char buffer for reading client sock
    char bc;
    
    //Helping variables
    char method[64];
    char url[128];
    char protocol[64];

    //Client address length
    socklen_t clilen;
    socklen_t address_length;
    
    //String buffer for reading client request
    charArr buffer;
    //String buffer for reading file contents
    charArr fileBuffer;
    //String buffer for response contents
    charArr responseBuffer;
    
    //Filepointer
    FILE *fp;
    
    
    //Client address and server address
    struct sockaddr_in serverAddr, clientAddr;

    /**
        HTTP response, header for valid requests dokument body should be appended on GET requests
    */
    static char* ok_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: text/html\n"
        "\n";

    /* 
        HTTP response, header, and body indicating that the we didn't
        understand the request.  
    */
    static char* bad_request_response = 
        "HTTP/1.0 400 Bad Request\n"
        "Content-type: text/html\n"
        "\n"
        "<html>\n"
        " <body>\n"
        "  <h1>400 Bad Request</h1>\n"
        "  <p>This server did not understand your request.</p>\n"
        " </body>\n"
        "</html>\n";

    /* 
        HTTP response, header, and body template indicating that the
        requested document was not found.  
    */
    static char* forbidden_response = 
        "HTTP/1.0 403 Forbidden\n"
        "Content-type: text/html\n"
        "\n"
        "<html>\n"
        " <body>\n"
        "  <h1>403 Forbidden</h1>\n"
        "  <p>Permission denied.</p>\n"
        " </body>\n"
        "</html>\n";

    /* 
        HTTP response, header, and body template indicating that the
        requested document was not found.  
    */
    static char* not_found_response = 
        "HTTP/1.0 404 Not Found\n"
        "Content-type: text/html\n"
        "\n"
        "<html>\n"
        " <body>\n"
        "  <h1>404 Not Found</h1>\n"
        "  <p>The requested URL was not found on this server.</p>\n"
        " </body>\n"
        "</html>\n";

    /* 
        HTTP response, header, and body template indicating that the
        method was not understood.  
    */
    static char* internal_server_error_response = 
        "HTTP/1.0 500 Internal server error\n"
        "Content-type: text/html\n"
        "\n"
        "<html>\n"
        " <body>\n"
        "  <h1>500 Internal Server Error</h1>\n"
        "  <p>Something went wrong.</p>\n"
        " </body>\n"
        "</html>\n";

    /* 
        HTTP response, header, and body template indicating that the
        method was not understood.  
    */
    static char* bad_method_response = 
        "HTTP/1.0 501 Method Not Implemented\n"
        "Content-type: text/html\n"
        "\n"
        "<html>\n"
        " <body>\n"
        "  <h1>501 Method Not Implemented</h1>\n"
        "  <p>The method %s is not implemented by this server.</p>\n"
        " </body>\n"
        "</html>\n";

    /**
        Init variables
    */
    // Init tcp/ip stream socket for server
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    // Check if socket was created properly
    if (serverSock < 0) {
        error("ERROR opening socket");
    }
    // Clear the server address
    bzero((char *) &serverAddr, sizeof(serverAddr));
    // Set the port
    portNr = 8888;
    // Set the socket family to tcp/ip
    serverAddr.sin_family = AF_INET;
    // Allow any connection addresses
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    // Sets the port number
    serverAddr.sin_port = htons(portNr);
    // Sets the clientLength
    clilen = sizeof(clientAddr);
    //Defaults nr of bytes read to 0
    rval = 0;
    //set value of optval
    optval = 1;
    //Init buffer arrays
    initArr(&fileBuffer, 128);
    initArr(&buffer, 128);
    initArr(&responseBuffer, 256);

    //Make sure that binds reuse server address so we don't get bind errors on restarts
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    // Binds the socket to the server and checks that it worked
    if (bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        error("ERROR on binding");
    }

    /**
        Start Server thingies
    */

    // Listen to the socket
    listen(serverSock,10);
    int cntr = 0;
    while(1) {
        cntr++;
        printf("COUNTER: %d\n", cntr);
        clientSock = -1;
        // Accepts the client
        clientSock = accept(serverSock, (struct sockaddr *) &clientAddr, &clilen);

        /* Get the remote address of the connection.  */
        address_length = sizeof (serverAddr);
        rval = getpeername (clientSock, (struct sockaddr *) &serverAddr, &address_length);
        /* Print a message.  */
        printf ("connection accepted from %s\n", inet_ntoa (serverAddr.sin_addr));

        // Checks if accept was successfull
        if (clientSock < 0) {
            error("ERROR on accept");
        }

        /**
            Resets variables
        */
        resetArr(&buffer);
        resetArr(&fileBuffer);
        resetArr(&responseBuffer);
        catArr(&responseBuffer, ok_response, strlen(ok_response));
        rval = 0;

        /*
            Read the client request to buffer
        */
        while (strstr (buffer.array, "\r\n\r\n") == NULL && buffer.array[0] != '\n' )
        {
            read(clientSock, &bc, 1);
            addArr(&buffer, bc);
        }

        //extracts the method, url and protocoll from the buffer
        sscanf (buffer.array, "%s %s %s", method, url, protocol);

        if(DEBUG) {
            /**
                Prints the buffer for "science!"
            */
            printf("CLIENT REQUEST: \n");
            for(i = 0; i < buffer.used; i++) {
                printf("%c", buffer.array[i]);
            }
            printf("Method: %s\n", method);
            printf("Url: %s\n", url);
            printf("Protocol: %s\n", protocol);
        }

        //Removes first slash of requested url
        memmove(url, url+1, strlen(url));
        //If url is now empty change url to index.html
        if(strlen(url) == 0) {
            strcpy (url, "index.html");
        }

        /**
            Read file based on url
        */
        printf("READING FILE: %s\n",url);
        fp = fopen(url, "r");
        if(fp != NULL) {
            while ((fc = fgetc(fp)) != EOF)
            {
                fc = (char) fc;
                addArr(&fileBuffer, fc);
            }
            addArr(&fileBuffer, '\0');
            if(DEBUG) {
                /**
                    Prints the fileBuffer for "science!"
                */
                printf("FILE CONENTES: \n");
                for(i = 0; i < fileBuffer.used; i++) {
                    printf("%c", fileBuffer.array[i]);
                }
            }
        }
        else{
            // do 404
            resetArr(&responseBuffer);
            catArr(&responseBuffer, not_found_response, strlen(not_found_response));
        }

        catArr(&responseBuffer, fileBuffer.array, fileBuffer.used);
        // Writes to the client and stores resultcode in rval
        rval = write(clientSock, responseBuffer.array, responseBuffer.used);
        // Closes client socket
        close(clientSock);
    }
}


/**
    logs an error and exits the program with error code 1
*/
void error(const char *msg) {
    perror(msg);
    exit(1);
}


/**
    Initialize a new array
*/
void initArr(charArr* arr, size_t startSize) {
    arr->array = (char *)malloc(startSize * sizeof(char));
    arr->used = 0;
    arr->size = startSize;
}

/**
    Add item to array
*/
void addArr(charArr* arr, char item) {
    if (arr->used == arr->size) {
        arr->size *= 2;
        arr->array = (char *)realloc(arr->array, arr->size * sizeof(char));
    }
    arr->array[arr->used++] = item;
}

void catArr(charArr* arr, char* items, int arrLen) {
    int i;
    for(i = 0; i < arrLen; i++) {
        addArr(arr, items[i]);
    }
}

/**
    Free allocated memory of arr
*/
void freeArr(charArr* arr) {
    int i;
    for(i = 0; i < arr->used; i++) {
        arr->array[i] = 0;
    }
    free(arr->array);
    arr->array = NULL;
    arr->used = arr->size = 0;
}
void resetArr(charArr* arr) {
    size_t originalSize = arr->size;
    freeArr(arr);
    initArr(arr, originalSize);
}