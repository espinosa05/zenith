
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifndef ZENITH_SERVER_BACKLOG
#define ZENITH_SERVER_BACKLOG 0x10
#endif /* ZENITH_SERVER_BACKLOG */

#define HTTP_REQUEST_TOKEN_COUNT 3 /* example token 1: GET token 2: /index.html token 3: HTTP/1.0\r\n */
#define REQUEST_TYPE_TOKEN_INDEX 0 /* first token of the request that holds the type, resource and version info */

#ifndef MAX_HTTP_HEADER_FIELDS
#define MAX_HTTP_HEADER_FIELDS 20
#endif /* MAX_HTTP_HEADER_FIELDS */
#define MAX_REQUEST_LEN sysconf(_SC_PAGESIZE)
#define MAX_RESPONSE_LEN sysconf(_SC_PAGESIZE)

#define MAX_HEADER_LEN (sysconf(_SC_PAGESIZE) / 2)
#define MAX_CONTENT_LEN (sysconf(_SC_PAGESIZE) / 2)

#define TODO(str) printf("[TODO]\t%s\n", str)
#define SA struct sockaddr

#define HTTP_END_OF_REQUEST_STR "\r\n\r\n"
#define HTTP_END_OF_REQUEST_SIZE strlen(HTTP_END_OF_REQUEST_STR)

/* zenith error handler files */
#ifndef ZENITH_ERR_PATH_PREFIX
#define ZENITH_ERR_PATH_PREFIX "./resources/"
#endif /* ZENITH_ERR_PATH_PREFIX */

#define ERR_404_HANDLER_FILE_PATH ZENITH_ERR_PATH_PREFIX "404.html"
#define ERR_418_HANDLER_FILE_PATH ZENITH_ERR_PATH_PREFIX "418.html"

#define ZENITH_SERVER_IPV4_ADDRESS  "127.0.0.1"

#define CONST_STRLEN(const_str) ((sizeof(const_str) / sizeof(const_str[0])) - 1)


enum response_str_idx {
    RESPONSE_200_OK = 0,
    RESPONSE_404_NOT_FOUND,
    RESPONSE_418_IM_A_TEAPOT,

    N_RESPONSES,
};

char *g_response_strs[N_RESPONSES] = {
    "OK",
    "Not Found",
    "I'm a teapot"
};

enum request_errors {
    SUCCESS = 0,
    CONNECTION_CLOSED,
    INVALID_REQUEST,
    REQUEST_TOO_LARGE,
};

enum request_header_field_types {
    HOST = 0,
    USER_AGENT,
    ACCEPT,
    ACCEPT_LANGUAGE,
    ACCEPT_ENCODING,
    CONNECTION,
    CONTENT_TYPE,
    CONTENT_LENGTH,
    AUTHORIZATION,
    COOKIE,

    HTTP_HEADER_FIELD_TYPE_COUNT,
};

struct http_response_struct_def {
    ssize_t header_size;
    ssize_t content_size;

    char *header;
    char *content;

    char *response_buf;
};

struct http_request_struct_def {
    ssize_t request_buf_size;
    char *request_buf_base;

    char *type;
    char *useragent;
    char *resource_path;
};

typedef struct http_request_struct_def *http_request;
typedef struct http_response_struct_def *http_response;

http_response init_http_response()
{
    struct http_response_struct_def *response_s = malloc(sizeof(struct http_response_struct_def));
    memset(response_s, 0, sizeof(struct http_response_struct_def));

    return (http_response)response_s;
}

http_request init_http_request()
{
    struct http_request_struct_def *request_s = malloc(sizeof(struct http_request_struct_def));
    request_s->request_buf_size = MAX_REQUEST_LEN;
    request_s->request_buf_base = malloc(request_s->request_buf_size);

    return (http_request)request_s;
}

void delete_http_response(http_response response)
{
    struct http_response_struct_def *response_s = (struct http_response_struct_def *)response;

    free(response_s->header);
    free(response_s->content);
    free(response_s);
}

void delete_http_request(http_request request)
{
    struct http_request_struct_def *request_s = (struct http_request_struct_def *)request;

    free(request_s->request_buf_base);
    free(request_s);
}

void throw_err_and_die(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void clear_sock_stream(int stream)
{
    char garbage_buf[1024];
    int nbytes;

    do {
        nbytes = read(stream, garbage_buf, sizeof(garbage_buf));
        
        if (nbytes == -1) {
            perror("recv failed");
            break;
        }

    } while(nbytes != 0);
}

size_t load_request(int confd, http_request request)
{
    int byte_cnt;
    struct http_request_struct_def *request_s = (struct http_request_struct_def *)request;
    puts("read");
    byte_cnt = read(confd, request_s->request_buf_base, MAX_REQUEST_LEN);
    puts("done");
    request_s->request_buf_size = byte_cnt;
    request_s->request_buf_base[byte_cnt] = '\0';
    if (byte_cnt == 0)
        return CONNECTION_CLOSED;

    if (byte_cnt < HTTP_END_OF_REQUEST_SIZE)
        return INVALID_REQUEST;

    /* check if the request ends with \r\n\r\n */
    if (strncmp(&request_s->request_buf_base[byte_cnt - HTTP_END_OF_REQUEST_SIZE], HTTP_END_OF_REQUEST_STR, HTTP_END_OF_REQUEST_SIZE) != 0) {
        return INVALID_REQUEST;
    }

    return SUCCESS;
}

void parse_request(http_request request)
{
    struct http_request_struct_def *request_s = (struct http_request_struct_def *)request;
    char *token_ptrs[MAX_HTTP_HEADER_FIELDS + HTTP_REQUEST_TOKEN_COUNT];
    char *http_token_saveptr;
    char *http_request_type_saveptr;

    int token_count;
    token_ptrs[0] = strtok_r(request_s->request_buf_base, "\r\n", &http_token_saveptr);

    for (token_count = 1; token_count < MAX_HTTP_HEADER_FIELDS; ++token_count) {
        token_ptrs[token_count] = strtok_r(NULL, "\r\n", &http_token_saveptr);

         if (token_ptrs[token_count] == NULL) {
            break;
         }
     }

    /* the request type is the first token */
 
    request_s->type = strtok_r(token_ptrs[REQUEST_TYPE_TOKEN_INDEX], " ", &http_request_type_saveptr);
    request_s->resource_path = strtok_r(NULL, " ", &http_request_type_saveptr);

    /* compare the tokens to the header fields that are supported by the server */
    /* the strcmp is not a mistake! */
    for (int i = 0; i < token_count; ++i) {
        
        if (strncmp(token_ptrs[i], "Host: ", CONST_STRLEN("Host: ")) == 0) {

        } else if (strncmp(token_ptrs[i], "User-Agent: ", CONST_STRLEN("User-Agent: ")) == 0) {
            request_s->useragent = &token_ptrs[i][CONST_STRLEN("User-Agent")];

        } else if (strncmp(token_ptrs[i], "Accept: ", CONST_STRLEN("Accept: ")) == 0) {
            TODO("implement the accepted mimetypes");

        } else if (strncmp(token_ptrs[i], "Accept-Language: ", CONST_STRLEN("Accept-Language: ")) == 0) {
            TODO("implement the accepted languages");

        } else if (strncmp(token_ptrs[i], "Accept-Encoding: ", CONST_STRLEN("Accept-Encoding: ")) == 0) {
            TODO("implement the accepted encodings");

        }
    }
}

void convert_server_path(char *path_buf, char *server_path)
{
    realpath(".", path_buf);

    strncat(path_buf, server_path, PATH_MAX - strlen(path_buf));
}

char *get_response_string(int response_code)
{
    switch(response_code) {
        case 200:
            return g_response_strs[RESPONSE_200_OK];
        case 404:
            return g_response_strs[RESPONSE_404_NOT_FOUND];
        case 418:
            return g_response_strs[RESPONSE_418_IM_A_TEAPOT];
        default:
            printf("invalid response code %d", response_code);
            exit(EXIT_FAILURE);
    }
}

void build_response(http_request request, http_response response)
{
    char absolute_resource_path[PATH_MAX];
    int response_code = 200;
    off_t response_file_size;
    ssize_t bytes_read;
    struct http_request_struct_def *request_s = (struct http_request_struct_def *)request;
    struct http_response_struct_def *response_s = (struct http_response_struct_def *)response;

    convert_server_path(absolute_resource_path, request_s->resource_path);

    int resource_fd = open(absolute_resource_path, O_RDONLY);

    if (resource_fd == -1) {
        switch(errno) {
            case ENOENT:
                response_code = 404;
                resource_fd = open(ERR_404_HANDLER_FILE_PATH, O_RDONLY);
                break;

            default:
                response_code = 418;
                resource_fd = open(ERR_418_HANDLER_FILE_PATH, O_RDONLY);
        }

        if (resource_fd == -1) {
            
            perror("failed to handle error!");

            exit(EXIT_FAILURE);
        }
    }

    response_file_size = lseek(resource_fd, 0, SEEK_END);
    
    if (response_file_size == -1) {
        perror("lseek");
        exit(EXIT_FAILURE);
    }

    lseek(resource_fd, 0, SEEK_SET);

    if (response_file_size >= MAX_CONTENT_LEN) {
        printf("file too large!");
        return;
    }

    response_s->content = malloc(response_file_size + 1);
   
    bytes_read = read(resource_fd, response_s->content, response_file_size);
   

    if (bytes_read == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    response_s->content[bytes_read] = '\0';
    response_s->response_buf = malloc(MAX_RESPONSE_LEN + 1);
    response_s->header = malloc(MAX_HEADER_LEN);

    TODO("dynamic content type");

    snprintf(response_s->header, MAX_HEADER_LEN,
                "Content-Length: %d\r\n"
                "Content-Type: %s\r\n",
                strlen(response_s->content),
                "text/html; charset=utf-8");

    snprintf(response_s->response_buf, MAX_RESPONSE_LEN, "HTTP/1.1 %d %s\r\n%s\r\n%s",
                response_code,
                get_response_string(response_code),
                response_s->header,
                response_s->content);

    free(response_s->content);
    free(response_s->header);
}

void send_response(int confd, http_response response)
{
    struct http_response_struct_def *response_s = (struct http_response_struct_def *)response;
    size_t response_size = strlen(response_s->response_buf);
    printf("response buf:\n%s\n", response_s->response_buf);
    send(confd, response_s->response_buf, response_size, 0);
    free(response_s->response_buf);
}

void hide_cli_cursor()
{
    printf("\033[?25l");
}

void show_cli_cursor()
{
    printf("\033[?25h");
}

void break_server_loop(int param)
{

    printf("\nclosing server!");
    putc('\n', stdout);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int server_socket;
    size_t sockopt_reuseaddr;
    socklen_t s_len;
    struct sockaddr_in server_address;
    http_request request;
    http_response response;


    setvbuf(stdout, NULL, _IONBF, 0);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket == -1)
        throw_err_and_die("socket call failed");



    sockopt_reuseaddr = 1;

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt_reuseaddr, sizeof(sockopt_reuseaddr)) == -1)
        throw_err_and_die("failed to set socket option SO_REUSEADDR");

    s_len = sizeof(server_address);

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = inet_addr(ZENITH_SERVER_IPV4_ADDRESS);


    if (bind(server_socket, (SA *)&server_address, s_len) == -1)
        throw_err_and_die("failed to bind socket");

    if (listen(server_socket, ZENITH_SERVER_BACKLOG) == -1)
        throw_err_and_die("failed to listen");

    printf("listening on port 8080\n");

    request = init_http_request();
    response = init_http_response();

    hide_cli_cursor();

    signal(SIGINT, break_server_loop);
    atexit(show_cli_cursor);

    while (1) {
        int connection_socket;
        socklen_t c_len;
        size_t request_status;
        struct sockaddr_in client_address;

        c_len = sizeof(client_address);
        printf("waiting for clients to connect...");
        
        connection_socket = accept(server_socket, (SA *)&client_address, &c_len);
        printf("\nconnection!");
        if (connection_socket == -1) {
            perror("failed to establish connection");
            continue;
        }

        request_status = load_request(connection_socket, request);

        if (request_status == CONNECTION_CLOSED
                || request_status == INVALID_REQUEST) {

            close(connection_socket);
            continue;
        }

        parse_request(request);
        build_response(request, response);
        send_response(connection_socket, response);
        close(connection_socket);
        printf("connection closed!\n");
    }

    show_cli_cursor();

    delete_http_request(request);
    delete_http_response(response);

    return EXIT_SUCCESS;
}