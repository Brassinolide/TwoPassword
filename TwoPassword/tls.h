/*
class MyTLS
{
public:
    MyTLS():_ctx(0), _ssl(0), _socket(0) {}
    ~MyTLS() {
        WSACleanup();
        SSL_shutdown(_ssl);
        SSL_free(_ssl);
        closesocket(_socket);
        SSL_CTX_free(_ctx);
    }

    bool connect(const char* address, u_short port) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }

        _socket = socket(AF_INET, SOCK_STREAM, 0);
        if (_socket == INVALID_SOCKET) {
            return false;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, address, &server_addr.sin_addr);
    
        const SSL_METHOD* method = TLS_client_method();
        _ctx = SSL_CTX_new(method);
        if (!_ctx) {
            // ERR_print_errors_fp(stderr);
            return false;
        }

        SSL_CTX_set_min_proto_version(_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(_ctx, TLS1_3_VERSION);
        SSL_CTX_set_ciphersuites(_ctx, "TLS_AES_256_GCM_SHA384");
        SSL_CTX_set1_curves_list(_ctx, "X25519");

        _ssl = SSL_new(_ctx);
        if (!_ssl) {
            return false;
        }

        SSL_set_fd(_ssl, _socket);

        if (SSL_connect(_ssl) <= 0) {
            return false;
        }

        return true;
    }

    bool set_cert_from_file(const char* cert) {
        if (!cert) {
            return false;
        }

        X509_STORE* store = SSL_CTX_get_cert_store(_ctx);
        if (!store) {
            return false;
        }

        X509* root_cert = nullptr;
        FILE* fp = fopen(cert, "r");
        if (!fp) {
            return false;
        }

        root_cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        fclose(fp);

        if (!root_cert) {
            return false;
        }

        if (X509_STORE_add_cert(store, root_cert) != 1) {
            X509_free(root_cert);
            return false;
        }

        X509_free(root_cert);

        SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, nullptr);

        SSL_CTX_set_verify_depth(_ctx, 1);

        return true;
    }

    void write(const void* buffer, size_t length) {
        SSL_write(_ssl, buffer, length);
    }

    void recv(void* buffer, size_t length) {
        SSL_read(_ssl, buffer, length);
    }
private:
    SSL_CTX* _ctx;
    SSL* _ssl;
    SOCKET _socket;
};

int main() {
    MyTLS tls;
    tls.set_cert_from_file("root.cer");
    tls.connect("127.0.0.1", 443);
    while (1) {
        tls.write("hello", 5);
    }
   
    return 0;
}
*/
