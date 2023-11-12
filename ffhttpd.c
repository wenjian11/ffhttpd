#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

typedef int (*PFN_CGI_MAIN)(char *request_type, char *request_path, char *url_args, char *request_data, int request_size, char *content_type, int ctypebuf_size, char *page_buf, int pbuf_size);

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#define dlopen(a, b) LoadLibrary(a)
#define dlclose(a)   FreeLibrary(a)
#define dlsym(a, b)  GetProcAddress(a, b)
#ifdef MSVC
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)
#define strcasecmp _stricmp
#endif
#else
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define  closesocket close
#define  SOCKET      int
#endif

// 将大写字母变成小写，如果本身就是小写，就不改变
static char* my_strlwr(char *s)
{
    char *p = s;
    while (*p) { *p += *p > 'A' && *p < 'Z' ? 'a' - 'A' : 0; p ++; }
    return s;
}

#define FFHTTPD_MAX_CONNECTIONS  8
#define FFHTTPD_MAX_WORK_THREADS FFHTTPD_MAX_CONNECTIONS

static char *g_ffhttpd_head1 =
"HTTP/1.1 %s\r\n"
"Server: ffhttpd/1.0.0\r\n"
"Accept-Ranges: bytes\r\n"
"Content-Type: %s\r\n"
"Content-Length: %d\r\n"
"Connection: close\r\n\r\n";

static char *g_ffhttpd_head2 =
"HTTP/1.1 206 Partial Content\r\n"
"Server: ffhttpd/1.0.0\r\n"
"Content-Range: bytes %d-%d/%d\r\n"
"Content-Type: %s\r\n"
"Content-Length: %d\r\n"
"Connection: close\r\n\r\n";

static char *g_404_page =
"<html>\r\n"
"<head><title>404 Not Found</title></head>\r\n"
"<body>\r\n"
"<center><h1>404 Not Found</h1></center>\r\n"
"<hr><center>ffhttpd/1.0.0</center>\r\n"
"</body>\r\n"
"</html>\r\n";

static char *g_content_type_list[][2] = {
    { ".asf" , "video/x-ms-asf"                 },
    { ".avi" , "video/avi"                      },
    { ".bmp" , "application/x-bmp"              },
    { ".css" , "text/css"                       },
    { ".exe" , "application/x-msdownload"       },
    { ".gif" , "image/gif"                      },
    { ".htm" , "text/html"                      },
    { ".html", "text/html"                      },
    { ".ico" , "image/x-icon"                   },
    { ".jpeg", "image/jpeg"                     },
    { ".jpg" , "image/jpeg"                     },
    { ".mp3" , "audio/mp3"                      },
    { ".mp4" , "video/mp4"                      },
    { ".pdf" , "application/pdf"                },
    { ".png" , "image/png"                      },
    { ".ppt" , "application/x-ppt"              },
    { ".swf" , "application/x-shockwave-flash"  },
    { ".tif" , "image/tiff"                     },
    { ".tiff", "image/tiff"                     },
    { ".txt" , "text/plain"                     },
    { ".wav" , "audio/wav"                      },
    { ".wma" , "audio/x-ms-wma"                 },
    { ".wmv" , "video/x-ms-wmv"                 },
    { ".xml" , "text/xml"                       },
    { NULL },
};

static char g_root_path[256] = ".";
static int  g_server_port    = 8080;
static int  g_exit_server    = 0;

// 获取文件类型
static char* get_content_type(char *file)
{
    int   i;
    char *ext = file + strlen(file);
    while (ext > file && *ext != '.') ext--;
    if (ext != file) {
        for (i=0; g_content_type_list[i][0]; i++) {
            if (strcasecmp(g_content_type_list[i][0], ext) == 0) {
                return g_content_type_list[i][1];
            }
        }
    }
    return "application/octet-stream";
}

// 
static void get_file_range_size(char *file, int *start, int *end, int *size)
{
    FILE *fp = NULL;
    char  path[1024];
    // 生成文件路径
    snprintf(path, sizeof(path), "%s/%s", g_root_path, file);
    // 二进制打开
    fp = fopen(path, "rb");
    if (fp) {
        // 到达文件末尾
        fseek(fp, 0, SEEK_END);
        // 获取指针fp当前位置相对于文件开头的偏移量，即文件大小
        *size = ftell(fp);
        fclose(fp);
        if (*start < 0) *start = *size + *start;
        if (*end >= *size) *end = *size - 1;
    } else {
        *start = *end = 0;
        *size  = -1;
    }
}

// 发送文件
static void send_file_data(SOCKET fd, char *file, int start, int end)
{
    FILE *fp = NULL;
    char  path[1024];
    // 生成文件路径
    snprintf(path, sizeof(path), "%s/%s", g_root_path, file);
    // 打开文件
    fp = fopen(path, "rb");
    if (fp) {
        char buf[1024];
        int  len = end - start + 1, ret = 0, n;
        fseek(fp, start, SEEK_SET);
        do {
            n = len < sizeof(buf) ? len : sizeof(buf);
            n = (int)fread(buf, 1, n, fp);
            len -= n > 0 ? n : 0;
            while (n > 0) {
                ret = send(fd, buf, n, 0);
#ifdef WIN32
                if (ret == 0 || (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != WSAEINTR)) goto done;
#else
                if (ret == 0 || (ret < 0 && errno != EWOULDBLOCK && errno != EINTR)) goto done;
#endif
                n  -= ret > 0 ? ret : 0;
            }
        } while (len > 0 && !feof(fp));
done:   fclose(fp);
    }
}

static void parse_range_datasize(char *str, int *partial, int *start, int *end, int *size)
{
    char *range_start, *range_end, *temp;
    *start = 0;
    *end   = 0x7FFFFFFF;
    *size  = 0;
    if (!str) return;
    // 搜索range第一次出现的位置
    range_start = strstr(str, "range");
    if (range_start && (range_end = strstr(range_start, "\r\n"))) {
        if (strstr(range_start, ":") && strstr(range_start, "bytes") && (range_start = strstr(range_start, "="))) {
            range_start += 1;
            // 获取start的值
            *start = atoi(range_start);
            if (*start < 0) {
                // 如果有-号先跳过，后面还会再找-，避免被这里的符号干扰
                range_start  = strstr(range_start, "-");
                range_start += 1;
            }
            range_start = strstr(range_start, "-");
            if (range_start && range_start + 1 < range_end) {
                range_start += 1;
                *end = atoi(range_start);
            }
        }
    }
    temp = strstr(str, "content-length");
    if (temp) {
        temp += 14;
        temp  = strstr(temp, ":");
        if (temp) *size = atoi(temp+1);
    }
    // 强转为bool类型
    *partial = !!range_start;
}

static char* parse_params(const char *str, const char *key, char *val, int len)
{
    char *p = (char*)strstr(str, key);
    int   i;

    *val = '\0';
    if (!p) return NULL;
    p += strlen(key);
    if (*p == '\0') return NULL;
    // 
    while (*p) {
        if (*p != ':' && *p != ' ') break;
        else p++;
    }

    for (i=0; i<len; i++) {
        if (*p == '\\') p++;
        else if (*p == '\r' || *p == '\n') break;
        val[i] = *p++;
    }
    val[i] = val[len-1] = '\0';
    return val;
}

typedef struct {
    int    head;
    int    tail;
    int    size; // size == -1 means exit
    SOCKET conns[FFHTTPD_MAX_CONNECTIONS];
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    pthread_t       threads[FFHTTPD_MAX_WORK_THREADS];
} THEADPOOL;

// 从线程池中取出一个fd
static SOCKET threadpool_dequeue(THEADPOOL *tp)
{
    SOCKET fd = -1;
    pthread_mutex_lock(&tp->mutex);
    while (tp->size == 0) pthread_cond_wait(&tp->cond, &tp->mutex);
    if (tp->size != -1) {
        fd = tp->conns[tp->head++ % FFHTTPD_MAX_CONNECTIONS];
        tp->size--;
        pthread_cond_signal(&tp->cond);
    }
    pthread_mutex_unlock(&tp->mutex);
    return fd;
}

// 放入一个fd到线程池中
static void threadpool_enqueue(THEADPOOL *tp, SOCKET fd)
{
    pthread_mutex_lock(&tp->mutex);
    while (tp->size == FFHTTPD_MAX_CONNECTIONS) pthread_cond_wait(&tp->cond, &tp->mutex);
    if (tp->size != -1) {
        tp->conns[tp->tail++ % FFHTTPD_MAX_CONNECTIONS] = fd;
        tp->size++;
        pthread_cond_signal(&tp->cond);
    }
    pthread_mutex_unlock(&tp->mutex);
}


static void* handle_http_request(void *argv)
{
    THEADPOOL *tp = (THEADPOOL*)argv;
    int    length, request_datasize, range_start, range_end, range_size, partial;
    char   recvbuf[1024], sendbuf[1024], cgibuf[8196], content_type[64];
    char  *request_type = NULL, *request_path = NULL, *url_args = NULL, *request_head = NULL, *request_data = NULL;
    SOCKET conn_fd;

    while ((conn_fd = threadpool_dequeue(tp)) != -1) {
        length = recv(conn_fd, recvbuf, sizeof(recvbuf)-1, 0);
        if (length <= 0) {
            printf("recv error or client close http connection !\n"); fflush(stdout);
            goto _next;
        }
        recvbuf[length] = '\0';
        printf("request :\n%s\n", recvbuf); fflush(stdout);
        /**
         * @brief 
         * GET /index.html HTTP/1.1
            Host: localhost:8080
            Connection: keep-alive
            sec-ch-ua: "Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"
            sec-ch-ua-mobile: ?0
            sec-ch-ua-platform: "Windows"
            Upgrade-Insecure-Requests: 1
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0
            Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7     
            Sec-Fetch-Site: none
            Sec-Fetch-Mode: navigate
            Sec-Fetch-User: ?1
            Sec-Fetch-Dest: document
            Accept-Encoding: gzip, deflate, br
            Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
         */
        // 第一个\r\n后面就是request_head部分
        request_head = strstr(recvbuf, "\r\n");
        if (request_head) {
            printf("ssssss\n");
            request_head[0] = 0; //相当于将\r换成了\0，将请求行和请求头分割开了
            request_head   += 2;
            printf("request_head1: %s", request_head);
            my_strlwr(request_head);
            printf("request_head2: %s", request_head);
            // 出现两次\r\n的地方就是请求体了，
            request_data = strstr(request_head, "\r\n\r\n");
            if (request_data) {
                printf("ddddddd\n");
                request_data[0] = 0;
                request_data   += 4;
            }
            // 从请求体中解析出content-length字段值到sendbuf中
            parse_params(request_head, "content-length", sendbuf, sizeof(sendbuf));
            // 解析出具体的值
            request_datasize = atoi(sendbuf);
            printf("request_datasize: %d\n", request_datasize);
        }
        request_type = recvbuf;
        // 这个空格是在GET后面，将这个空格置为0之后，就会将request_type分割出来
        request_path = strstr(recvbuf, " ");
        if (request_path) {
            // 相当于 GET\0/index.html HTTP/1.1,此时request_path指向/
           *request_path++ = 0;
            request_path   = strstr(request_path, "/");
            // 此时的request_path后面还有别的数据
            printf("request_path: %s\n", request_path);  // /index.html HTTP/1.1
        }
        if (request_path) {
            // 跳过/
            request_path  += 1;
            // index.html HTTP/1.1，找空格，并置为0，分割开
            url_args = strstr(request_path, " ");
            if (url_args) *url_args   = 0;
            url_args = strstr(request_path, "?");
            if (url_args) *url_args++ = 0;
            // request_path在上面++了，如果/后面没有内容，则指定为默认路径
            if (!request_path[0]) request_path = "index.html";
        }

        parse_range_datasize(request_head, &partial, &range_start, &range_end, &range_size);
        //                   GET, request_path: index.html, url_args: (null), range_size: 0, request_datasize: 0
        printf("request_type: %s, request_path: %s, url_args: %s, range_size: %d, request_datasize: %d\n", request_type, request_path, url_args, range_size, request_datasize); fflush(stdout);

        get_file_range_size(request_path, &range_start, &range_end, &range_size);
        // 上面的函数会去打开请求路径的文件，如果打开失败，表示文件不存在，range_size = -1
        if (range_size == -1) { // 404
            // 将404放入sendbuf中
            length = snprintf(sendbuf, sizeof(sendbuf), g_ffhttpd_head1, "404 Not Found", "text/html", strlen(g_404_page));
            printf("aaa: %s", sendbuf); fflush(stdout);
            send(conn_fd, sendbuf, length, 0);
            send(conn_fd, g_404_page, (int)strlen(g_404_page), 0);
            goto _next;
        } 

        length = request_path ? (int)strlen(request_path) : 0;
        // 如果请求的是某个cgi文件
        if (length > 4 && strcmp(request_path + length - 4, ".cgi") == 0) {
            void *dl = NULL;
            snprintf(cgibuf, sizeof(cgibuf), "./%s", request_path);
            // 打开动态链接库文件
            dl = dlopen(cgibuf, RTLD_LAZY);
            if (dl) {
                // 找到这个动态链接库文件中的指定的方法
                PFN_CGI_MAIN cgimain  = (PFN_CGI_MAIN)dlsym(dl, "cgimain");
                int          pagesize = 0;
                // 如果找到这个方法
                if (cgimain) {
                    strncpy(content_type, "text/html", sizeof(content_type));
                    strncpy(cgibuf, "", sizeof(cgibuf));
                    pagesize = cgimain(request_type, request_path, url_args, request_data, request_datasize, content_type, sizeof(content_type), cgibuf, sizeof(cgibuf));
                }
                dlclose(dl);
                // 后面的三个为占位符填充内容
                snprintf(sendbuf, sizeof(sendbuf), g_ffhttpd_head1, "200 OK", content_type, pagesize);
                // 先发送头部
                send(conn_fd, sendbuf, (int)strlen(sendbuf), 0);
                // 在发送内容，bgibuf中的内容是通过加载动态库的函数，然后将对应的内容写入到cgibuf中的
                send(conn_fd, cgibuf , pagesize, 0);
            }
        } else if (strcmp(request_type, "GET") == 0 || strcmp(request_type, "HEAD") == 0) {
            if (!partial) {
                length = snprintf(sendbuf, sizeof(sendbuf), g_ffhttpd_head1, "200 OK", get_content_type(request_path), range_size);
            } else {
                length = snprintf(sendbuf, sizeof(sendbuf), g_ffhttpd_head2, range_start, range_end, range_size, get_content_type(request_path), range_size ? range_end - range_start + 1 : 0);
            }
            printf("response:\n%s\n", sendbuf); fflush(stdout);
            /**
             * @brief 
             * HTTP/1.1 200 OK
                Server: ffhttpd/1.0.0
                Accept-Ranges: bytes
                Content-Type: text/html
                Content-Length: 499
                Connection: close
             */
            // 发送头文件
            send(conn_fd, sendbuf, length, 0);
            if (strcmp(request_type, "GET") == 0) {
                send_file_data(conn_fd, request_path, range_start, range_end);
            }
        }

_next:  closesocket(conn_fd);
    }
    return NULL;
}

// 初始化线程池
static void threadpool_init(THEADPOOL *tp)
{
    int i;
    // 设置为0
    memset(tp, 0, sizeof(THEADPOOL));
    // 对mutex变量初始化
    pthread_mutex_init(&tp->mutex, NULL);
    // 对cond变量初始化
    pthread_cond_init (&tp->cond , NULL);
    // 循环创建线程，每个现场绑定函数为handle_http_request，其参数为线程池
    for (i=0; i<FFHTTPD_MAX_WORK_THREADS; i++) pthread_create(&tp->threads[i], NULL, handle_http_request, tp);
}

// 释放线程池
static void threadpool_free(THEADPOOL *tp)
{
    int i;
    pthread_mutex_lock(&tp->mutex);
    // 置为-1表示退出
    tp->size = -1;
    // 通知其他线程，其他线程会被唤醒去检测tp->size的值，如果为-1,其他线程也会退出
    pthread_cond_broadcast(&tp->cond);
    pthread_mutex_unlock(&tp->mutex);
    for (i=0; i<FFHTTPD_MAX_WORK_THREADS; i++) pthread_join(tp->threads[i], NULL);
    // 销毁mutex变量
    pthread_mutex_destroy(&tp->mutex);
    // 销毁cond变量
    pthread_cond_destroy (&tp->cond );
}

// 信号处理函数
static void sig_handler(int sig)
{
    struct sockaddr_in server_addr;
    SOCKET client_fd;
    printf("sig_handler %d\n", sig); fflush(stdout);
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        g_exit_server = 1;
        client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client_fd != -1) {
            server_addr.sin_family      = AF_INET;
            server_addr.sin_port        = htons(g_server_port);
            server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                closesocket(client_fd);
            }
        }
        break;
    }
}

int main(int argc, char *argv[])
{
    struct sockaddr_in server_addr, client_addr;
    SOCKET    server_fd, conn_fd;
    int       addrlen = sizeof(client_addr), i;
    THEADPOOL thread_pool;
    // 重置新的端口号和根目录
    for (i=1; i<argc; i++) {
        if      (strstr(argv[i], "--port=") == argv[i]) g_server_port = atoi(argv[i] + 7);
        else if (strstr(argv[i], "--root=") == argv[i]) strncpy(g_root_path, argv[i] + 7, sizeof(g_root_path));
    }
    printf("port: %d, root: %s\n", g_server_port, g_root_path);

#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        exit(1);
    }
#endif

    // 注册信号处理函数
    signal(SIGINT , sig_handler);
    signal(SIGTERM, sig_handler);
    // 指定协议
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(g_server_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("failed to open socket !\n"); fflush(stdout);
        exit(1);
    }
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("failed to bind !\n"); fflush(stdout);
        exit(1);
    }
    if (listen(server_fd, FFHTTPD_MAX_CONNECTIONS) == -1) {
        printf("failed to listen !\n"); fflush(stdout);
        exit(1);
    }

    threadpool_init(&thread_pool);
    // 循环监听客户端连接，并将新的连接放入到线程池中
    while (!g_exit_server) {
        conn_fd = accept(server_fd, (struct sockaddr*)&client_addr, (void*)&addrlen);
        if (conn_fd != -1) threadpool_enqueue(&thread_pool, conn_fd);
        else printf("failed to accept !\n");
    }
    threadpool_free(&thread_pool);

    closesocket(server_fd);
#ifdef WIN32
    WSACleanup();
#endif
    return 0;
}

