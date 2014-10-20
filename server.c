/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h> 
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
    CONSTANTS
*/
enum {DEBUG=0};

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

void handleRequest(int clientSock, charArr* url);
void handleResponse(int clientSock, charArr* url, char* method);

int sendOkHeaders(int clientSock, char* ext);
int sendNotFound(int clientSock);
int sendBadRequest(int clientSock);
int sendBadMethod(int clientSock);
int sendInternalError(int clientSock);
int sendForbidden(int clientSock);

int loadDefaultVariables(char* configFile, charArr* defaultPath);
/**
    Main file
*/
int main(int argc, char *argv[])
{

    /**
        Declare variables
    */
    int serverSock, clientSock, portNr, rval, optval, i, isDaemon;
    socklen_t clilen, addressLength;
    pid_t childPid;
    struct sockaddr_in serverAddr, clientAddr;
    char* configFile = ".lab3-config";
    charArr defaultPath;
    initArr(&defaultPath, 25);
    portNr = loadDefaultVariables(configFile, &defaultPath);
    /**
        Init variables
    */
    isDaemon = 0;
    // Parse argv
    for(i = 0; i < argc; i++) {
        // Set port if defined
        if(!strcmp(argv[i], "-p")) {
            portNr = strtol(argv[++i], (char **)NULL, 10);
            printf("Use port: %d\n", portNr);
        }
        //Enable daemon mode if defined
        if(!strcmp(argv[i], "-d")) {
            isDaemon = 1;
            printf("Enable Daemon mode\n", portNr);
        }
    }
    printf("PORT: %d\n", portNr);
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {error("ERROR opening socket");}
    // Clear the server address
    bzero((char *) &serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET; // Set the socket family to tcp/ip
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Allow any connection addresses
    serverAddr.sin_port = htons(portNr); // Sets the port number
    clilen = sizeof(clientAddr);
    rval = 0;
    optval = 1;
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
    listen(serverSock,20);
    printf("Server is now listening for clients\n\n");
    while(1) {
        /* accepts the client */
        clientSock = accept(serverSock, (struct sockaddr *) &clientAddr, &clilen);
        if (clientSock < 0) {error("ERROR on accept");}

        /* Get the remote address of the connection. */
        addressLength = sizeof (serverAddr);
        rval = getpeername (clientSock, (struct sockaddr *) &serverAddr, &addressLength);
        printf("connection accepted from %s\n", inet_ntoa (serverAddr.sin_addr));

        /* Fork a child process to handle the connection.  */
        childPid = fork();
        if (childPid == 0) {
            /* This child process shouldn't do anything with the listening socket. */
            close(serverSock);

            /* Handle request with a clientSock copy */
            handleRequest(clientSock, &defaultPath);
            /* All done; close the connection socket, and end the child
            process.  */
            close(clientSock);
            exit(0);
        }
        else if (childPid > 0) {
            /* This is the parent process.  The child process handles the
            connection, so we don't need our copy of the connected socket
            descriptor.  Close it.  Then continue with the loop and
            accept another connection.  */
            close (clientSock);
        }
        else {
            /* Call to fork failed.  */
            error("fork");
        }
    }
}


/**
    Handle the request and respond to the client
*/
void handleRequest(int clientSock, charArr* url) {
    /**
        Define variables
    */
    //Char buffer for reading client sock
    char bc;
    //Helping variables
    char method[64];
    char raw_url[128];
    char protocol[64];
    //String buffers
    charArr buffer;

    //Init buffer array
    initArr(&buffer, 128);

    /* Read the client request to buffer */
    while (strstr (buffer.array, "\r\n\r\n") == NULL && buffer.array[0] != '\n' ) {
        read(clientSock, &bc, 1);
        addArr(&buffer, bc);
    }
    //extracts the method, url and protocoll from the buffer
    sscanf (buffer.array, "%s %s %s", method, raw_url, protocol);
    catArr(url, raw_url+1, strlen(raw_url)-1);
    freeArr(&buffer);
    handleResponse(clientSock, url, method);
    freeArr(url);
}
void handleResponse(int clientSock, charArr* url, char* method) {
    int rval, fd, fileSize;
    char* ext;
    struct stat file_stat;
    //Removes first slash of requested url
    //memmove(url, url+1, strlen(url));
    //If url is now empty change url to index.html
    if(!strcmp(&url->array[url->used-1], "/")) {
        catArr(url, "index.html", strlen("index.html"));
        url->array[url->used] = '\0'; //FIXME
    }
    printf("    Client requested: %s\n", url->array);
    
    /* Try to deliver the requested file */
    fd = open(url->array, O_RDONLY);
    if(fd != -1) {
        ext = strrchr(url->array, '.');
        if (!ext) {
            addArr(url, '/');
            handleResponse(clientSock, url, method);
            return;
            //File has no extension... 400?
            //printf("    Read error, file is a directory, FIXME\n");
            //rval = sendBadRequest(clientSock);
            //return;
        } else {
            ext++;
        }
        /* Get file stats */
        fstat(fd, &file_stat);
        fileSize = file_stat.st_size;
        if(DEBUG) {printf("    Method: %s\n", method);}
        if(!strcmp(method, "GET")) {
            rval = sendOkHeaders(clientSock, ext);
            rval = sendfile (clientSock, fd, NULL, fileSize);
            printf("    Delivered file: %s\n", url->array);
        } else if (!strcmp(method, "HEAD")){
            rval = sendOkHeaders(clientSock, ext);
        } else {
            printf("Unsupported method: %s\n", method);
            sendBadRequest(clientSock);
        }
    } else {
        if(errno == 17) {
            //Read error, file exists
            //send 500 internal server error.
            printf("Read error: File exists, server is broken\n");
            rval = sendInternalError(clientSock);
        } else if(errno == 21) {
            //read error, file is a directory
            //enable fancy url parser that delivers index.html or 404?
            printf("Read error, file is a directory, FIXME\n");
            rval = sendBadRequest(clientSock);
        } else {
            rval = sendNotFound(clientSock);
            printf("File %s not found\n", url->array);
        }
    }
}



int sendOkHeaders(int clientSock, char* ext) {
    /**
        HTTP response, header for valid requests dokument body should be appended on GET requests
    */
    charArr response;
    initArr(&response, 50);
    char* jpgExt = "jpg";
    char* pngExt = "png";
    char* gifExt = "gif";
    char* cssExt = "css";
    char* jsExt = "js";
    static char* ok_html_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: text/html\n"
        "\n";
    static char* ok_jpg_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: image/jpeg\n"
        "\n";
    static char* ok_png_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: image/png\n"
        "\n";
    static char* ok_gif_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: image/gif\n"
        "\n";
    static char* ok_css_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: text/css\n"
        "\n";
    static char* ok_js_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: text/javascript\n"
        "\n";
    if(!strcmp(jpgExt, ext)) {
        catArr(&response, ok_jpg_response, strlen(ok_jpg_response));
    }else if(!strcmp(pngExt, ext)){
        catArr(&response, ok_png_response, strlen(ok_png_response));
    }else if(!strcmp(gifExt, ext)){
        catArr(&response, ok_gif_response, strlen(ok_gif_response));
    }else if(!strcmp(cssExt, ext)){
        catArr(&response, ok_css_response, strlen(ok_css_response));
    }else if(!strcmp(jsExt, ext)){
        catArr(&response, ok_js_response, strlen(ok_js_response));
    }else{
        catArr(&response, ok_html_response, strlen(ok_html_response));
    }
    int rval = write(clientSock, response.array, response.used);
    freeArr(&response);
    return rval;
}
int sendNotFound(int clientSock) {
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
    return write(clientSock, not_found_response, strlen(not_found_response));
}
int sendBadRequest(int clientSock) {
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
    return write(clientSock, bad_request_response, strlen(bad_request_response));
}
int sendBadMethod(int clientSock) {
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
    return write(clientSock, bad_method_response, strlen(bad_method_response));
}
int sendInternalError(int clientSock) {
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
    return write(clientSock, internal_server_error_response, strlen(internal_server_error_response));
}
int sendForbidden(int clientSock) {
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
    return write(clientSock, forbidden_response, strlen(forbidden_response));
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

int loadDefaultVariables(char* configFile, charArr* defaultPath) {
    charArr fileBuffer;
    int fd, portBuffer;
    char bc;
    char* rval;
    char* baseUrl = "/home/pi/shellScripting/Lab2/C/CWebserver/www/";
    int basePort = 8888;
    initArr(&fileBuffer, 10);
    /* Read the defaultPath */
    fd = open(configFile, O_RDONLY);
    while (fileBuffer.array[fileBuffer.used-1] != '\n' ) {
        read(fd, &bc, 1);
        addArr(&fileBuffer, bc);
    }
    rval = strrchr(fileBuffer.array, ':');
    if(!rval) {
        printf("No default url found\n");
        //No default path found... use default default...
        rval = baseUrl;
    } else {
        rval++;
    }
    catArr(defaultPath, rval, strlen(rval)-1);
    resetArr(&fileBuffer);
    /* Read the defaultPort */
    while (fileBuffer.array[fileBuffer.used-1] != '\n' ) {
        read(fd, &bc, 1);
        addArr(&fileBuffer, bc);
    }
    rval = strrchr(fileBuffer.array, ':');
    if(!rval) {
        printf("no default port found\n");
        //No default path found... use default default...
        portBuffer = basePort;
    } else {
        rval++;
        portBuffer = strtol(rval, (char **)NULL, 10);
    }
    return portBuffer;
}