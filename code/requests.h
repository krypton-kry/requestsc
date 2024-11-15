/* date = November 11th 2024 10:39 pm */

#ifdef REQUESTS_IMPLEMENTATION

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif // USE_OPENSSL

#ifdef USE_BEARSSL
#include <bearssl.h>
#endif //USE_BEARSSL

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#define GETSOCKETERRNO() (WSAGetLastError())

#elif __linux__
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#define GETSOCKETERRNO() (errno)

#else
# error "Unknown device"
#endif //OS

#define internal static inline

#define u64 uint64_t
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t

// TODO(krypton): add more
typedef enum {
    GET,
    POST
} request_type;

typedef enum {
    HTTP,
    HTTPS
} request_scheme;

// NOTE(krypton):  we only support chunked, right?
typedef enum {
    TRANSFER_NULL,
    TRANSFER_DIRECT,
    TRANSFER_CHUNKED,
    TRANSFER_COMPRESS,
    TRANSFER_DEFLATE,
    TRANSFER_GZIP,
} transfer_encoding;

typedef struct {
    void* ssl_ctx;
    void* ssl;
    u32 sock;
    u8* hostname;
    u8* host_path;
    u8* port;
} requests;

// TODO(krypton): do a separate header struct?
typedef struct {
    u32 status_code;
    transfer_encoding transfer_type;
    u8* data;
} response;

static requests* ctx;

typedef struct {
    u8* data;
    u64 size;
} data_chunk;

typedef struct {
    request_type scheme;
    u8* user_name;
    u8* password;
    u8* domain; // or ip
    u8* port;
    u8* path;
} url_info;
// scheme://USERNAME:PASSWORD@domain/PATH

internal void requests_init();
internal void requests_cleanup();
// NOTE(krypton) : this function need to have the args because if the user wants to get just the info he should be able to get it without setting the context
internal struct addrinfo* r_getaddrinfo(u8* hostname, u8* port);
internal u8 r_socket_connect();
internal response _request(u8* url, request_type type);
internal response r_process(data_chunk* data);
internal void r_parse_url(u8* url, url_info* info);

internal void os_socket_init();
internal void os_socket_cleanup();
internal void os_socket_close(u32 sock);

internal void os_ssl_init();
internal void os_ssl_cleanup();
internal u8 os_ssl_connect();
internal data_chunk os_ssl_recv();
internal void os_ssl_send(u8* data, u64 data_len);

internal void* os_memmem(void *src, u32 srclen, void *trg, u32 trglen);

internal void
requests_init(){
    ctx = malloc(sizeof(requests));
    memset(ctx, 0, sizeof(ctx));
    
    os_socket_init();
    os_ssl_init();
    
}

internal void
requests_cleanup(){
    os_ssl_cleanup();
    os_socket_cleanup();
    free(ctx);
}

internal struct addrinfo*
r_getaddrinfo(u8* hostname, u8* port){
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;
    
    struct addrinfo *peer_address = {0};
    if (!getaddrinfo(hostname, port, &hints, &peer_address)) {
        // TODO(krypton) : what to do when this fails ? 
    } else {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
    }
    
    return peer_address;
}

// TODO(krypton): is this alright ? 
// TODO(krypton): does this need a separate connect function so we can hold the connection (for sessions ?)
// TODO(krypton): TOFIX check if hostname and port exist ? 
// NOTE(krypton): returns one if succeded zero if failed 
internal u8 
r_socket_connect(){
    struct addrinfo* addr = r_getaddrinfo(ctx->hostname, ctx->port);
    u32 server = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    
    if (server > 0) {
        ctx->sock = server;
        if(!connect(ctx->sock,
                    addr->ai_addr, addr->ai_addrlen)) {
            // NOTE (krypton) : nothing here ig?
            return 1;
        } else {
            fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        }
    } else {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
    }
    
    freeaddrinfo(addr);
    return 0;
}

internal data_chunk r_recv(){
    
    u64 total_bytes_received = 0;
    u32 data_len = 2048;
    u8* data = malloc(data_len);
    
    while(1) {
        u32 bytes_received = recv(ctx->sock, data+total_bytes_received, data_len-total_bytes_received, 0);
        if (bytes_received < 1) {
            break;
        }
        total_bytes_received += bytes_received;
        
        if (total_bytes_received >= data_len) {
            data_len *= 2;
            u8* new_data = realloc(data, data_len);
            
            if (new_data) {
                data = new_data;  
            }
        }
    }
    
    return (data_chunk){
        .data = data,
        .size = total_bytes_received
    };
}

#define request(url, type) _request((u8[]){url}, type);
// in linux (clang), static links are placed in read only memory and can't be modified!
internal response 
_request(u8* url, request_type type){
    url_info info = {0};
    r_parse_url(url, &info);
    
    ctx->hostname = info.domain;
    ctx->port = info.port;
    ctx->host_path = info.path;
    
    if(r_socket_connect()){
        if(info.scheme == HTTP){
            switch(type){
                case GET:
                {
                    
                    u8 buffer[2048];
                    
                    sprintf(buffer, "GET /%s HTTP/1.1\r\n", ctx->host_path);
                    sprintf(buffer + strlen(buffer), "Host: %s:%s\r\n", ctx->hostname, ctx->port);
                    sprintf(buffer + strlen(buffer), "Connection: close\r\n");
                    sprintf(buffer + strlen(buffer), "User-Agent: Mozilla/5.0 \r\n");
                    sprintf(buffer + strlen(buffer), "\r\n");
                    
                    if(send(ctx->sock, buffer, sizeof(buffer), 0)< 0 ){
                        assert(0);
                    }
                    
                    data_chunk res = r_recv();
                    response resp = r_process(&res);
                    
                    return resp;
                    free(res.data);
                } break;
                case POST:
                {
                } break;
                default:
                break;
            }
        } else if (info.scheme == HTTPS){
            
            if(os_ssl_connect()){
                switch(type){
                    case GET:
                    {
                        
                        u8 buffer[2048];
                        
                        sprintf(buffer, "GET /%s HTTP/1.1\r\n", ctx->host_path);
                        sprintf(buffer + strlen(buffer), "Host: %s:%s\r\n", ctx->hostname, ctx->port);
                        sprintf(buffer + strlen(buffer), "Connection: close\r\n");
                        sprintf(buffer + strlen(buffer), "User-Agent: Mozilla/5.0 \r\n");
                        sprintf(buffer + strlen(buffer), "\r\n");
                        
                        os_ssl_send(buffer, sizeof(buffer));
                        data_chunk res = os_ssl_recv();
                        response resp = r_process(&res);
                        
                        return resp;
                        free(res.data);
                    } break;
                    case POST:
                    {
                    } break;
                    default:
                    break;
                }
            }
            
        } else {
            
            // TODO(krypton):  error
            assert(0 && "Why are you here?");
        }
    }
    return (response){0};
}

internal response 
r_process(data_chunk* data){
    u8* ptr = data->data;
    u8* header_end = os_memmem(ptr, data->size, "\r\n\r\n", 4);
    response resp = {0};
    
    if(header_end){
        u64 header_size = (u64)(header_end - ptr);
        u8* head = malloc(header_size + 1);
        
        head[header_size] = '\0';
        memcpy(head, ptr, header_size);
        // TODO(krypton):  parse and check if chunked
        
        ptr = data->data;
        
        while(ptr && *ptr != '\r' && *ptr != '\0'){
            u8* line_end = os_memmem(ptr, header_size, "\r\n", 2);
            if(!line_end) break;
            
            if(strncmp(ptr, "HTTP/", 5) == 0){
                u8* start= strchr(ptr, ' ');
                while(*start == ' ') start++;
                resp.status_code = strtol(start, 0, 10);
            }
            
            if(strncmp(ptr, "Transfer-Encoding:", 18) == 0){
                u8* start = ptr + 18;
                while(*start == ' ') start++;
                if(strncmp(start, "chunked", 7) == 0){
                    resp.transfer_type = TRANSFER_CHUNKED;
                } else {
                    assert(0);
                }
            } else {
                // NOTE(krypton): if Transfer-Encoding doesnt exist we need to check if Content-Length exists
                if(strncmp(ptr, "Content-Length:", 15) == 0){
                    resp.transfer_type = TRANSFER_DIRECT;
                }
            }
            
            ptr = line_end + 2;
        }
        
        // it should be either direct/chunked
        assert(resp.transfer_type != TRANSFER_NULL);
        
        free(head);
        ptr = data->data;
        if(resp.transfer_type == TRANSFER_CHUNKED){
            u32 body_size = 1024;
            u8* body_data = malloc(body_size);
            u64 total_body_bytes = 0;
            
            ptr = ptr + header_size + 4;
            
            while(ptr && *ptr != '\0'){
                u8* line_end = os_memmem(ptr, data->size - header_size - 4, "\r\n", 2);// 4 to skip \r\n\r\n from header
                if(!line_end) break;
                
                u8 chunk_length_buff[32] = {0};
                u32 chunk_size_len = line_end - ptr;
                memcpy(chunk_length_buff, ptr, chunk_size_len);
                u64 chunk_size = strtoll(chunk_length_buff, 0, 16);  
                
                if(chunk_size == 0) break;
                
                if(total_body_bytes + chunk_size > body_size){
                    body_size = (body_size + chunk_size) * 2;
                    u8* new_data = realloc(body_data, body_size);
                    if(new_data) body_data = new_data;
                }
                
                ptr = line_end + 2;
                
                memcpy(body_data + total_body_bytes, ptr, chunk_size);
                total_body_bytes += chunk_size;
                ptr += chunk_size + 2;
            }
            
            // TODO(krypton): is there a need to realloc with +1 byte ?
            body_data[total_body_bytes] = '\0';
            
            resp.data = body_data; 
        }
        
        if(resp.transfer_type == TRANSFER_DIRECT){
            // TODO(krypton):  Read Content-Length or just strlen?
            u64 body_size = data->size - header_size - 4;
            u8* body = malloc(body_size + 1); // -4 for \r\n\r\n + 1 for string terminator
            memcpy(body, data->data + header_size + 4, body_size);
            body[body_size] = '\0';
            
            resp.data = body;
        }
        
    } else {
        // TODO(krypton): error
    }
    
    // TODO(krypton):  Should i free data->data here? 
    return resp;
}


// TODO(krypton):  return values
internal void 
r_parse_url(u8* url, url_info* info){
    // TODO(krypton):  Sanitize the url first
    u8* loc = memchr(url, ':', 6);
    if(loc == 0){
        assert(0 && "invalid url");
    }
    
    *loc = '\0';
    
    if(!strcmp(url, "http")){
        info->port = "80";
        info->scheme = HTTP;
    } else if(!strcmp(url, "https")){
        info->port = "443";
        info->scheme = HTTPS;
    } else {
        assert(0 && "Only HTTP/HTTPS supported");
    }
    
    if(!(loc[1] == '/' || loc[2] == '/')){
        assert(0 && "Invalid URL");
    }
    
    // TODO(krypton): Support Username password in url
    // TODO(krypton): Support port from url (also extract it from the url)
    
    u8* domain = loc + 3;
    info->domain = domain;
    u8* path = memchr(domain, '/', strlen(domain));
    
    if(path == 0){
        info->path = "/";
    } else {
        *path = '\0';
        info->path = path+1;
    }
}

#ifdef USE_OPENSSL

internal void 
os_ssl_init(){
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
    }
    
    ctx->ssl_ctx = ssl_ctx;
    
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new() failed.\n");
    }
    
    ctx->ssl = ssl;
    
}

internal void 
os_ssl_cleanup(){
    SSL_shutdown(ctx->ssl);
    SSL_free(ctx->ssl);
    SSL_CTX_free(ctx->ssl_ctx);
}

// TODO(krypton): handle failure
// NOTE(krypton): returns one if succeded zero if failed 
internal u8 
os_ssl_connect(){
    
    if (SSL_set_tlsext_host_name(ctx->ssl, ctx->hostname)) {
        
        SSL_set_fd(ctx->ssl, ctx->sock);
        if (SSL_connect(ctx->ssl) != -1) {
            return 1;
        } else {
            fprintf(stderr, "SSL_connect() failed.\n");
            ERR_print_errors_fp(stderr);
        }
    } else {
        fprintf(stderr, "SSL_set_tlsext_host_name() failed.\n");
        ERR_print_errors_fp(stderr);
    }
    
    return 0;
}

// TODO(krypton): int returns
internal void 
os_ssl_send(u8* data, u64 data_len){
    if(!SSL_write(ctx->ssl, data, data_len)){
        fprintf(stderr, "SSL_write() failed.\n");
        ERR_print_errors_fp(stderr);
    }
}

internal data_chunk 
os_ssl_recv(){
    u64 total_bytes_received = 0;
    u32 data_len = 2048;
    u8* data = malloc(data_len);
    
    while(1) {
        u32 bytes_received = SSL_read(ctx->ssl, data+total_bytes_received, data_len-total_bytes_received);
        if (bytes_received < 1) {
            break;
        }
        total_bytes_received += bytes_received;
        
        if (total_bytes_received >= data_len) {
            data_len *= 2;
            u8* new_data = realloc(data, data_len);
            
            if (new_data) {
                data = new_data;
            }
        }
    }
    
    return (data_chunk){
        .data = data,
        .size = total_bytes_received
    };
    
}

#endif // USE_OPENSSL

#ifdef _WIN32

internal void 
os_socket_init(){
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "WIN32 : Failed to initialize.\n");
    }
}

internal void 
os_socket_cleanup(){
    WSACleanup();
}

internal void 
os_socket_close(u32 sock){
    closesocket(sock);
}

#elif __linux__

internal void os_socket_init(){}
internal void os_socket_cleanup(){}

internal void 
os_socket_close(u32 sock){
    close(sock);
}

#endif // OS

internal void*
os_memmem(void *src, u32 srclen, void *trg, u32 trglen)
{
    
    u8* csrc = (unsigned char *)src;
    u8* ctrg = (unsigned char *)trg;
    u8 *tptr,*cptr;
    u32 searchlen,ndx=0;
    
    // TODO(krypton): error check
    
    while (ndx<=srclen) {
        cptr = &csrc[ndx];
        if ((searchlen = srclen-ndx-trglen+1) <= 0) {
            return NULL;
        }
        if ((tptr = memchr(cptr,*ctrg,searchlen)) == NULL) {
            return NULL;
        }
        if (memcmp(tptr,ctrg,trglen) == 0) {
            return tptr;
        }
        ndx += tptr-cptr+1;
    }
    return NULL;
}

#endif //REQUESTS_IMPLEMENTATION
