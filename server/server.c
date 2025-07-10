/**
 * Secure File Transfer Server (TLS/SSL)
 * - Secure TLS connection supporting OpenSSL 1.0.2
 * - Concurrent connections handling
 * - TODO: file integrity verification
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Configuration
#define PORT 5060              // Porta di ascolto
#define BUFFER_SIZE 128*1024   // Dimensione buffer per I/O (128KB)
#define SYNC_FOLDER "./received"  // Cartella per i file ricevuti
#define TIMEOUT_SEC 10          // Timeout connessioni 
#define MAX_CHILDREN 50
volatile sig_atomic_t active_children = 0;

// SSL shared context
SSL_CTX *ssl_ctx;


void handle_sigpipe(int sig) {
    printf("[WARN] SIGPIPE received and ignored\n");
}

/* Gestore segnale per SIGCHLD */
void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if(WIFEXITED(status)) {
            printf("[INFO] Child %d exited with status %d\n", 
                  pid, WEXITSTATUS(status));
        }
        __sync_fetch_and_sub(&active_children, 1); // Decremento atomico
    }
}

 /* Inizializza le librerie OpenSSL */
 void init_openssl() {
    signal(SIGPIPE, handle_sigpipe); 
    SSL_load_error_strings();   // Carica i messaggi di errore SSL
    OpenSSL_add_ssl_algorithms(); // Inizializza algoritmi crittografici
    OpenSSL_add_all_algorithms(); 
    ERR_load_crypto_strings();
 }

 /* Estrae l'estensione del file */
const char* get_file_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";  // Nessuna estensione o punto all'inizio
    return dot;  // Restituisce l'estensione con il punto (es. ".bin")
}
 
/* Crea e configura il contesto SSL per il server */
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = SSLv23_server_method();  // dpbbiamo usare questo perche sull macchina abbiamo openssl 1.0.2
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    // Leggi paths da variabili d'ambiente
    const char* server_cert = getenv("SSL_CERT_FILE");
    const char* server_key = getenv("SSL_KEY_FILE");
    const char* ca_cert = getenv("SSL_CA_FILE");

    if (!server_cert || !server_key || !ca_cert) {
        fprintf(stderr, "Required SSL environment variables not set\n");
        fprintf(stderr, "Please set: SSL_CERT_FILE, SSL_KEY_FILE, SSL_CA_FILE\n");
        exit(EXIT_FAILURE);
    }
 
     // Carica certificato e chiave privata del server
    if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
     
    if (SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
 
    // Configura verifica client obbligatoria
    SSL_CTX_set_verify(ctx, 
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, // Richiede certificato client
        NULL);
    SSL_CTX_load_verify_locations(ctx, ca_cert, NULL);
     
    return ctx;
 }

 /* Gestione timeout socket */
void set_socket_timeout(int sockfd) {
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
 
/* Pulizia risorse OpenSSL */
void cleanup_openssl() {
    SSL_CTX_free(ssl_ctx);  // Libera il contesto SSL
    EVP_cleanup();          // Dealloca gli algoritmi
    ERR_free_strings();            
    CRYPTO_cleanup_all_ex_data();  
}
 
/* Verifica se un file esiste già nella cartella */
int file_exists(const char *filename) {
    char path[BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/%s", SYNC_FOLDER, filename);
    struct stat st;
    return (stat(path, &st) == 0); // Restituisce 1 se esiste, 0 altrimenti
}
 
/* Riceve un file attraverso la connessione SSL */
void receive_file(SSL *ssl, const char *filename, size_t filesize) {
    char buffer[BUFFER_SIZE] = {0};
    const char *basename = strrchr(filename, '/');
    basename = basename ? basename + 1 : filename; // Estrae solo il nome file
 
    char filepath[BUFFER_SIZE];
    snprintf(filepath, sizeof(filepath), "%s/%s", SYNC_FOLDER, basename);
 
    printf("[DEBUG] Receiving file: '%s'\n", filepath);
    mkdir(SYNC_FOLDER, 0700);  // Crea cartella se non esiste
 
    FILE *file = fopen(filepath, "wb");
    if (!file) {
        perror("[ERROR] Failed to open file");
        return;
    }
 
    // Costanti per il logging
    const size_t LOG_INTERVAL = 5242880; // 5 MB = 5*1024*1024 bytes
    size_t next_log = LOG_INTERVAL;
 
    printf("[+] Inizio ricezione: %s (%zu MB)\n", basename, filesize / (1024 * 1024));
 
    // Ricezione dati
    size_t bytes_received = 0;
    while (bytes_received < filesize) {
        int to_read = (filesize - bytes_received) < BUFFER_SIZE ? 
                      (filesize - bytes_received) : BUFFER_SIZE;
                      
        int read_bytes = SSL_read(ssl, buffer, to_read);
        if (read_bytes <= 0) {
            int err = SSL_get_error(ssl, read_bytes);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                printf("[INFO] Client disconnected\n");
            } else {
                printf("[ERROR] SSL read error: %d\n", err);
            }
            break;
        }
 
        fwrite(buffer, 1, read_bytes, file);
        bytes_received += read_bytes;
         
        // Log progressivo
        if (bytes_received >= next_log) {
            printf("[>] Progresso: %zu/%zu MB (%.1f%%)\n", 
                   bytes_received / (1024 * 1024), filesize / (1024 * 1024),
                   (double)bytes_received / filesize * 100);
                   next_log += LOG_INTERVAL;
        }
    }
 
    fclose(file);
 
    // Conferma finale al client
    if (bytes_received == filesize) {
        printf("[INFO] File received successfully\n");
        const char *end_msg = "END";
        if (SSL_write(ssl, end_msg, strlen(end_msg)) <= 0) {
            printf("[ERROR] Failed to send final confirmation\n");
        }
    } else {
        printf("[ERROR] Transfer incomplete: %zu/%zu bytes\n", bytes_received, filesize);
    }
}
 
/* Converte un errore X509 in stringa descrittiva */
const char* x509_error_string(long error_code) {
    switch (error_code) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "Certificate expired";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "Certificate not yet valid";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "Self-signed certificate";
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return "Self-signed certificate in chain";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "Unable to get local issuer certificate";
        case X509_V_ERR_CERT_REVOKED:
            return "Certificate revoked";
        case X509_V_ERR_INVALID_CA:
            return "Invalid CA certificate";
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            return "Path length constraint exceeded";
        case X509_V_ERR_INVALID_PURPOSE:
            return "Unsupported certificate purpose";
        case X509_V_ERR_CERT_UNTRUSTED:
            return "Certificate not trusted";
        default:
            return X509_verify_cert_error_string(error_code);
    }
}
 
/* Verifica le date di validità del certificato */
void check_certificate_dates(X509 *cert) {
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
     
    int days_remaining, seconds_remaining;
    int rc = X509_cmp_current_time(not_after);
     
    if(rc == 0) {
        fprintf(stderr, "[CERT ERROR] Invalid expiration time format\n");
    } else if(rc < 0) {
        fprintf(stderr, "[CERT ERROR] Certificate expired\n");
    }
     
    rc = X509_cmp_current_time(not_before);
    if(rc == 0) {
        fprintf(stderr, "[CERT ERROR] Invalid activation time format\n");
    } else if(rc > 0) {
        fprintf(stderr, "[CERT ERROR] Certificate not yet valid\n");
    }
}
 
/* Log dettagliato errori SSL */
void print_ssl_error(SSL *ssl, long verify_result) {
    fprintf(stderr, "Certificate verification failed. Details:\n");
    
    // Errore specifico della verifica
    fprintf(stderr, " - Verification error: %s (code %ld)\n", 
            x509_error_string(verify_result), verify_result);
    
    // Certificato ricevuto
    X509 *cert = SSL_get_peer_certificate(ssl);
    if(cert) {
        fprintf(stderr, " - Peer certificate details:\n");
        
        // Soggetto
        X509_NAME *subj = X509_get_subject_name(cert);
        BIO *bio = BIO_new(BIO_s_mem());
        X509_NAME_print_ex(bio, subj, 0, XN_FLAG_ONELINE);
        char *subj_str;
        BIO_get_mem_data(bio, &subj_str);
        fprintf(stderr, "   Subject: %s\n", subj_str);
        BIO_free(bio);
        
        // Emittente
        X509_NAME *issuer = X509_get_issuer_name(cert);
        bio = BIO_new(BIO_s_mem());
        X509_NAME_print_ex(bio, issuer, 0, XN_FLAG_ONELINE);
        char *issuer_str;
        BIO_get_mem_data(bio, &issuer_str);
        fprintf(stderr, "   Issuer: %s\n", issuer_str);
        BIO_free(bio);
        
        // Date di validità
        check_certificate_dates(cert);
        X509_free(cert);
    } else {
        fprintf(stderr, " - No peer certificate presented\n");
    }
    
    // Errori in coda OpenSSL
    fprintf(stderr, " - SSL errors queue:\n");
    ERR_print_errors_fp(stderr);
}
 
/* Gestisce una connessione client */
void handle_client(SSL *ssl) {
    // Verifica certificato client
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "Client without certificate\n");
        SSL_shutdown(ssl);
        return;
    }

    // Controlla validità certificato
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Invalid client certificate\n");
        print_ssl_error(ssl, verify_result);
        X509_free(cert);
        SSL_shutdown(ssl);
        return;
    }

    // Log informazioni client
    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Authenticated client: %s\n", subject);
    OPENSSL_free(subject);
    X509_free(cert);

    // Elaborazione trasferimenti
    char file_info[BUFFER_SIZE];
    while (1) {
        int message_length;
        int read_bytes = SSL_read(ssl, &message_length, sizeof(int));
        
        // Gestione disconnessione client
        if (read_bytes <= 0) {
            printf("[INFO] Client disconnected\n");
            break;
        }

        // Controllo dimensione metadati
        if (message_length > BUFFER_SIZE) {
            fprintf(stderr, "Metadata too large\n");
            break;
        }

        // Ricezione metadati in un ciclo
        size_t total_read = 0;
        while (total_read < message_length) {
            int read_bytes = SSL_read(ssl, file_info + total_read, message_length - total_read);
            if (read_bytes <= 0) {
                int err = SSL_get_error(ssl, read_bytes);
                if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                    printf("[INFO] Client disconnected\n");
                } else {
                    printf("[ERROR] SSL read error: %d\n", err);
                }
                break;
            }
            total_read += read_bytes;
        }
        if (total_read != message_length) {
            printf("[ERROR] Failed to read complete metadata\n");
            break;
        }
        file_info[total_read] = '\0';

        char *filename = strtok(file_info, ":");
        char *filesize_str = strtok(NULL, ":");
        
        // Verifica formato metadati
        if (!filename || !filesize_str) {
            fprintf(stderr, "Invalid metadata format\n");
            break;
        }

        size_t filesize = atol(filesize_str);
        printf("[DEBUG] Receiving: %s (%zu bytes)\n", filename, filesize);

        // Estrai e verifica l'estensione del file
        const char *extension = get_file_extension(filename);
        if (strcmp(extension, ".bin") != 0 && 
            strcmp(extension, ".bz2") != 0 && 
            strcmp(extension, ".gz") != 0) {
            printf("[INFO] Rejected file with invalid extension: %s\n", filename);
            SSL_write(ssl, "REJECT", 6);  // Invia rifiuto al client
            continue;  // Torna al ciclo per attendere nuovi metadati
        }

        // Controlla se il file esiste già
        if (!file_exists(filename)) {
            SSL_write(ssl, "ACK", 3);  // Autorizza trasferimento
            receive_file(ssl, filename, filesize);
        } else {
            SSL_write(ssl, "SKIP", 4); // Notifica file duplicato
        }
    }

    // Chiusura connessione SSL
    int shutdown_ret;
    do {
        shutdown_ret = SSL_shutdown(ssl);
    } while (shutdown_ret == 0);
    SSL_free(ssl);
}
 
/* Funzione principale del server */
int main() {
    // Inizializzazione OpenSSL
    init_openssl();
    ssl_ctx = create_ssl_context();

    // Configurazione socket
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    // Creazione socket TCP
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configura opzioni socket
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;  // Ascolta su tutte le interfacce

    // Binding socket
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
 
    // Inizio ascolto
    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
 
    printf("Server listening on port %d\n", PORT);
 
    // Loop principale accettazione connessioni
    while(1) {
        if(active_children >= MAX_CHILDREN) {
            printf("[WARN] Max connections reached (%d)\n", MAX_CHILDREN);
            sleep(1);
            continue;
        }
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
        active_children++;

        printf("[INFO] Accepted connection from %s:%d\n", 
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        
        if(fork() == 0) { // Processo figlio

            printf("[INFO] A\n");

            close(server_fd);
            
            printf("[INFO] B\n");

            SSL *ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_fd);
            set_socket_timeout(client_fd);

            printf("[INFO] C\n");

            if(SSL_accept(ssl) > 0) {

                printf("[INFO] SSL/TLS handshake successful\n");

                handle_client(ssl);
            } else {
                long verify_result = SSL_get_verify_result(ssl);
                if (verify_result != X509_V_OK) {
                    fprintf(stderr, "SSL/TLS handshake failed: %s\n", 
                            x509_error_string(verify_result));
                    print_ssl_error(ssl, verify_result);
                } else {
                    fprintf(stderr, "SSL/TLS handshake failed\n");
                }
            }

            printf("[INFO] D\n");
            
            close(client_fd);
            exit(0);
        }
        else { // Processo padre
            close(client_fd);
        }
    }
 
    cleanup_openssl();  // Pulizia finale (mai raggiunto in questo loop infinito)
    return 0;
}
