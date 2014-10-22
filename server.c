/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/types.h> 
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

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
}CharArr;
/**
    Declares a client info struct
*/
typedef struct {
    int socket;
    int bytesWritten;
    CharArr method;
    CharArr url;
    CharArr protocol;
    CharArr address;
    CharArr statusCode;
    CharArr logFile;
}ClientInfo;

/**
    Declares the function headers
*/
void initArr(CharArr* arr, size_t startSize);
void addArr(CharArr* arr, char item);
void catArr(CharArr* arr, char* items, int arrLen);
void freeArr(CharArr* arr);
void resetArr(CharArr* arr);

void error(const char *msg);

void handleRequest(ClientInfo* client, CharArr* url);
void handleResponse(ClientInfo* client, CharArr* url, CharArr* method);

int sendOkHeaders(ClientInfo* client, char* ext);
int sendNotFound(ClientInfo* client);
int sendBadRequest(ClientInfo* client);
int sendBadMethod(ClientInfo* client);
int sendInternalError(ClientInfo* client);
int sendForbidden(ClientInfo* client);

int loadDefaultVariables(char* configFile, CharArr* defaultPath);
int getHeaderInfo(ClientInfo* client, CharArr* buffer);

void getFormatedTime(char* buffer);
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
    CharArr defaultPath;
    ClientInfo client;
    client.socket = 0;
    client.bytesWritten = 0;
    initArr(&client.method, 16);
    initArr(&client.url, 32);
    initArr(&client.protocol, 16);
    initArr(&client.address, 32);
    initArr(&client.statusCode, 4);
    initArr(&client.logFile, 64);
    initArr(&defaultPath, 32);
    portNr = loadDefaultVariables(configFile, &defaultPath);
    syslog(LOG_INFO, "%s", "Webserver has started");
    mkdir("/home/jails", ACCESSPERMS);
    mkdir("/home/jails/webserver", ACCESSPERMS);
    if (chroot("/home/jails/webserver") != 0) {
        perror("/home/jails/webserver");
        return 1;
    } else {
        printf("Set /home/jails/webserver as root folder\n");
    }
    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "%s", "Successfully Jailed webserver to /home/jails/webserver");

    /**
        Init variables
    */
    isDaemon = 0;
    // Parse argv
    for(i = 0; i < argc; i++) {
        // Set port if defined
        if(!strcmp(argv[i], "-p")) {
            portNr = strtol(argv[++i], (char **)NULL, 10);
            printf("Using port: %d\n", portNr);
        }
        //Enable daemon mode if defined
        if(!strcmp(argv[i], "-d")) {
            isDaemon = 1;
            printf("Daemonmode activated\n", portNr);
        }
        //Enable log file if defined
        if(!strcmp(argv[i], "-l")) {
            catArr(&client.logFile, argv[++i], strlen(argv[i]));
            printf("LogFile set to: %s\n", client.logFile.array);
        }
    }
    if(isDaemon) {
        /* Our process ID and Session ID */
        pid_t pid, sid;
        /* Fork off the parent process */
        pid = fork();
        if (pid < 0) {
            exit(EXIT_FAILURE);
        }
        /* If we got a good PID, then
           we can exit the parent process. */
        if (pid > 0) {
            printf("Process id: %d\n", pid);
            exit(EXIT_SUCCESS);
        }
        /* Change the file mode mask */
        umask(0);
        /* Create a new SID for the child process */
        sid = setsid();
        if (sid < 0) {
            /* Log the failure */
            exit(EXIT_FAILURE);
        }
        
        /* Close out the standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
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
        client.socket = accept(serverSock, (struct sockaddr *) &clientAddr, &clilen);
        if (client.socket < 0) {error("ERROR on accept");}

        /* Get the remote address of the connection. */
        addressLength = sizeof(serverAddr);
        rval = getpeername(client.socket, (struct sockaddr *)&serverAddr, &addressLength);
        resetArr(&client.address);
        catArr(&client.address, inet_ntoa(serverAddr.sin_addr), strlen(inet_ntoa(serverAddr.sin_addr)));

        //Ignore the dying children
        signal(SIGCHLD, SIG_IGN);
        /* Fork a child process to handle the connection.  */
        childPid = fork();
        if (childPid == 0) {
            /* This child process shouldn't do anything with the listening socket. */
            close(serverSock);

            /* Handle request with a client.socket copy */
            handleRequest(&client, &defaultPath);
            /* All done; close the connection socket, and end the child
            process.  */
            close(client.socket);
            exit(0);
        }
        else if (childPid > 0) {
            /* This is the parent process.  The child process handles the
            connection, so we don't need our copy of the connected socket
            descriptor.  Close it.  Then continue with the loop and
            accept another connection.  */
            close (client.socket);
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
void handleRequest(ClientInfo* client, CharArr* url) {
    /**
        Define variables
    */
    FILE *fd;
    //Char buffer for reading client sock
    char bc;
    //Helping variables
    char timeBuffer[64];
    //String buffers
    CharArr buffer;

    //Init buffer array
    initArr(&buffer, 128);

    /* Read the client request to buffer */
    while (strstr (buffer.array, "\r\n\r\n") == NULL && buffer.array[0] != '\n' ) {
        read(client->socket, &bc, 1);
        addArr(&buffer, bc);
    }
    if(DEBUG) {printf("CLIENT REQUEST: %s\n", buffer.array);}
    //extracts the method, url and protocoll from the buffer
    if(getHeaderInfo(client, &buffer)) {
        //sscanf (buffer.array, "%s %s %s", method, raw_url, protocol);
        catArr(url, client->url.array, client->url.used);
        handleResponse(client, url, &client->method);
    }
    // TODO getdatestuff
    getFormatedTime(timeBuffer);
    if(client->logFile.used != 0) {
        fd = fopen(client->logFile.array, "a");
        fprintf(fd, "%s - - [%s] \"%s %s %s\" %s %d\n", client->address.array, timeBuffer, client->method.array, client->url.array, client->protocol.array, client->statusCode.array, client->bytesWritten);
        fclose(fd);
    }else {
        syslog(LOG_INFO, "%s - - [%s] \"%s %s %s\" %s %d", client->address.array, timeBuffer, client->method.array, client->url.array, client->protocol.array, client->statusCode.array, client->bytesWritten);
    }
    //printf("%s - - [%s] \"%s %s %s\" %s %d\n", client->address.array, timeBuffer, client->method.array, client->url.array, client->protocol.array, client->statusCode.array, client->bytesWritten);
    freeArr(&client->method);
    freeArr(&client->url);
    freeArr(&client->protocol);
    freeArr(&client->address);
    freeArr(&client->statusCode);
    freeArr(&client->logFile);
    freeArr(&buffer);
    freeArr(url);
}
void handleResponse(ClientInfo* client, CharArr* url, CharArr* method) {
    int rval, fd, fileSize;
    char* ext;
    struct stat file_stat;
    //If url is now empty change url to index.html
    if(!strcmp(&url->array[url->used-1], "/")) {
        catArr(url, "index.html", strlen("index.html"));
    }
    /* Try to deliver the requested file */
    fd = open(url->array, O_RDONLY);
    if(fd != -1) {
        ext = strrchr(url->array, '.');
        if (!ext) {
            addArr(url, '/');
            handleResponse(client, url, method);
            return;
            //File has no extension... 400?
        } else {
            ext++;
        }
        /* Get file stats */
        fstat(fd, &file_stat);
        fileSize = file_stat.st_size;
        if(DEBUG) {printf("    Method: %s\n", method->array);}
        if(!strcmp(method->array, "GET")) {
            rval = sendOkHeaders(client, ext);
            rval += sendfile (client->socket, fd, NULL, fileSize);
        } else if (!strcmp(method->array, "HEAD")){
            rval = sendOkHeaders(client, ext);
        } else {
            rval = sendBadRequest(client);
        }
    } else {
        if(errno == 17) {
            //Read error, file exists
            rval = sendInternalError(client);
        } else if(errno == 21) {
            //read error, file is a directory
            //printf("Read error, file is a directory, FIXME\n");
            rval = sendBadRequest(client);
        } else {
            rval = sendNotFound(client);
        }
    }
    if(rval > 0) {
        client->bytesWritten += rval;
    } else {
        rval = sendInternalError(client);
        client->bytesWritten += rval;
    }
}

int getHeaderInfo(ClientInfo* client, CharArr* buffer) {
    char bc;
    int counter = 0;
    int bytesWritten;

    //parse http method (GET, HEAD, etc)
    bc = buffer->array[counter++];
    while(bc != ' ' && counter < buffer->used) {
        addArr(&client->method, bc);
        bc = buffer->array[counter++];
    }

    //Parse requested url
    bc = buffer->array[counter++];
    while(bc != ' ' && client->url.used != 2000 && counter < buffer->used) {
        addArr(&client->url, bc);
        bc = buffer->array[counter++];
    }
    if(client->url.used == 2000 && counter < buffer->used) {
        while(bc != ' ') {
            bc = buffer->array[counter++];
        }
    }
    bc = buffer->array[counter++];
    while(bc != '\r' && counter < buffer->used) {
        addArr(&client->protocol, bc);
        bc = buffer->array[counter++];
    }

    if(strstr(client->url.array, "..") != NULL) {
        bytesWritten = sendForbidden(client);
        if(bytesWritten > 0) {
            client->bytesWritten += bytesWritten;
        }
        return 0;
    }

    if(strcasecmp(client->method.array, "GET") && strcasecmp(client->method.array, "HEAD")) {
        bytesWritten = sendBadMethod(client);
        if(bytesWritten > 0) {
            client->bytesWritten += bytesWritten;
        }
        return 0;
    }


    if(client->url.used == 2000 || counter >= buffer->used) {
        bytesWritten = sendBadRequest(client);
        if(bytesWritten > 0) {
            client->bytesWritten += bytesWritten;
        }
        return 0;
    }
    return 1;
}

int sendOkHeaders(ClientInfo* client, char* ext) {
    catArr(&client->statusCode, "200", strlen("200"));
    /**
        HTTP response, header for valid requests dokument body should be appended on GET requests
    */
    CharArr response;
    initArr(&response, 50);
    char* jpgExt = "jpg";
    char* pngExt = "png";
    char* gifExt = "gif";
    char* icoExt = "ico";
    char* cssExt = "css";
    char* jsExt = "js";
    static char* ok_html_response =
        "HTTP/1.0 200 OK\n"
        "content-type: text/html; charset=UTF-8\n"
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
    static char* ok_ico_response =
        "HTTP/1.0 200 OK\n"
        "Content-type: image/x-icon\n"
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
    }else if(!strcmp(icoExt, ext)){
        catArr(&response, ok_ico_response, strlen(ok_ico_response));
    }else if(!strcmp(cssExt, ext)){
        catArr(&response, ok_css_response, strlen(ok_css_response));
    }else if(!strcmp(jsExt, ext)){
        catArr(&response, ok_js_response, strlen(ok_js_response));
    }else{
        catArr(&response, ok_html_response, strlen(ok_html_response));
    }
    int rval = write(client->socket, response.array, response.used);
    freeArr(&response);
    return rval;
}
int sendNotFound(ClientInfo* client) {
    catArr(&client->statusCode, "404", strlen("404"));
    /* 
        HTTP response, header, and body template indicating that the
        requested document was not found.  
    */
    static char* not_found_response = 
        "HTTP/1.0 404 Not Found\n"
        "Content-type: text/html\n"
        "\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n"
        "<html>\n"
        " <head>\n"
        "  <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
        "  <title>404 Not Found</title>\n"
        " </head>\n"
        " <body>\n"
        "  <h1>404 Not Found</h1>\n"
        "  <p>The requested URL was not found on this server.</p>\n"
        " </body>\n"
        "</html>\n";
    return write(client->socket, not_found_response, strlen(not_found_response));
}
int sendBadRequest(ClientInfo* client) {
    catArr(&client->statusCode, "400", strlen("400"));
    /* 
        HTTP response, header, and body indicating that the we didn't
        understand the request.  
    */
    static char* bad_request_response = 
        "HTTP/1.0 400 Bad Request\n"
        "Content-type: text/html\n"
        "\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n"
        "<html>\n"
        " <head>\n"
        "  <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
        "  <title>400 Bad Request</title>\n"
        " </head>\n"
        " <body>\n"
        "  <h1>400 Bad Request</h1>\n"
        "  <p>This server did not understand your request.</p>\n"
        " </body>\n"
        "</html>\n";
    return write(client->socket, bad_request_response, strlen(bad_request_response));
}
int sendBadMethod(ClientInfo* client) {
    catArr(&client->statusCode, "501", strlen("501"));
    /* 
        HTTP response, header, and body template indicating that the
        method was not understood.  
    */
    static char* bad_method_response = 
        "HTTP/1.0 501 Method Not Implemented\n"
        "Content-type: text/html\n"
        "\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n"
        "<html>\n"
        " <head>\n"
        "  <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
        "  <title>501 Method Not Implemented</title>\n"
        " </head>\n"
        " <body>\n"
        "  <h1>501 Method Not Implemented</h1>\n"
        "  <p>The requested method is not implemented by this server.</p>\n"
        " </body>\n"
        "</html>\n";
    return write(client->socket, bad_method_response, strlen(bad_method_response));
}
int sendInternalError(ClientInfo* client) {
    catArr(&client->statusCode, "500", strlen("500"));
    /* 
        HTTP response, header, and body template indicating that the
        method was not understood.  
    */
    static char* internal_server_error_response = 
        "HTTP/1.0 500 Internal server error\n"
        "Content-type: text/html\n"
        "\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n"
        "<html>\n"
        " <head>\n"
        "  <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
        "  <title>500 Internal Server Error</title>\n"
        " </head>\n"
        " <body>\n"
        "  <h1>500 Internal Server Error</h1>\n"
        "  <p>Something went wrong.</p>\n"
        " </body>\n"
        "</html>\n";
    return write(client->socket, internal_server_error_response, strlen(internal_server_error_response));
}
int sendForbidden(ClientInfo* client) {
    catArr(&client->statusCode, "403", strlen("403"));
    /* 
        HTTP response, header, and body template indicating that the
        requested document was not found.  
    */
    static char* forbidden_response = 
        "HTTP/1.0 403 Forbidden\n"
        "Content-type: text/html\n"
        "\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n"
        "<html>\n"
        " <head>\n"
        "  <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
        "  <title>403 Forbidden</title>\n"
        " </head>\n"
        " <body>\n"
        "  <h1>403 Forbidden</h1>\n"
        "  <p>Permission denied.</p>\n"
        " </body>\n"
        "</html>\n";
    return write(client->socket, forbidden_response, strlen(forbidden_response));
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
void initArr(CharArr* arr, size_t startSize) {
    arr->array = (char *)malloc(startSize * sizeof(char));
    arr->used = 0;
    arr->size = startSize;
}

/**
    Add item to array
*/
void addArr(CharArr* arr, char item) {
    if (arr->used-1 == arr->size) {
        arr->size *= 2;
        arr->array = (char *)realloc(arr->array, arr->size * sizeof(char));
    }
    arr->array[arr->used++] = item;
    arr->array[arr->used] = '\0';
}

void catArr(CharArr* arr, char* items, int arrLen) {
    int i;
    for(i = 0; i < arrLen; i++) {
        addArr(arr, items[i]);
    }
}

/**
    Free allocated memory of arr
*/
void freeArr(CharArr* arr) {
    int i;
    for(i = 0; i < arr->used; i++) {
        arr->array[i] = 0;
    }
    free(arr->array);
    arr->array = NULL;
    arr->used = arr->size = 0;
}
void resetArr(CharArr* arr) {
    size_t originalSize = arr->size;
    freeArr(arr);
    initArr(arr, originalSize);
}

int loadDefaultVariables(char* configFile, CharArr* defaultPath) {
    CharArr fileBuffer;
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
    freeArr(&fileBuffer);
    return portBuffer;
}

void getFormatedTime(char* buffer) {
    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    strftime (buffer,80,"%d/%b/%Y:%H:%M:%S %z",timeinfo);
}