/**
 * Secure File Transfer Client (TLS/SSL + Compression)
 * - Secure TLS connection
 * - Optional compression using gzip
 * - Reliable transfer with ACK
 * - Automatic management of processed files
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
// #include <signal.h>
#include <zlib.h>
// #include <bzlib.h>

// Configurations
#define BUFFER_SIZE 1024    // I/O buffer dimension, increase to 64 KB or more in modern systems
#define PORT 5060              // Porta default
#define IP_LOCAL "127.0.0.1"         // IP default del server in locale
#define SYNC_FOLDER "/to-send"      // Cartella sorgente file
#define BASE_FOLDER "."
#define SENT_FOLDER "/sent"     // Cartella destinazione file inviati
#define ABSOLUTE_PATH "."
#define CERTIFICATE_PATH "./certs"
#define CLIENT_KEY_PATH "./certs/client.key.pem"
#define CLIENT_CERT_PATH "./certs/client.chain.cert.pem"
#define CA_CERT_PATH "./certs/ca.cert.pem"
#define GZIP_COMPRESSION_MODE "wb1"     // Gzip compression mode, use wb1 for fastest compression, wb for default
 
SSL_CTX *ssl_ctx;  // global SSL context

// Prototipi funzioni
void init_openssl();
SSL_CTX *create_ssl_context();
void cleanup_openssl();
void check_certificate_dates(X509 *cert);
const char* x509_error_string(long error_code);
void print_ssl_error(SSL *ssl, long verify_result);
void compress_file(const char *input_file, const char *output_file, int compression_type);
int send_file(SSL *ssl, const char *filename);
size_t get_file_size(const char *filename);
int is_regular_file(const char *path);
void move_file_to_sent(const char *filepat,const char *sent_folder);
int connect_with_timeout(int sock, const struct sockaddr *addr, socklen_t addrlen, int timeout_sec);
 

int main(int argc, char *argv[]) {

    // Configuration variables
    const char *ip = IP_LOCAL;
    int port = PORT;
    const char *base_path = BASE_FOLDER;
    int use_compression = 0;

    fprintf(stdout, "[INFO] Starting Secure File Transfer Client\n");

    // Command-line argument parsing
    // fprintf(stdout, "[INFO] Parsing command-line arguments\n");
    
    if (argc > 5) {
        fprintf(stderr, "[ERROR] Too many arguments provided. Usage: %s [IP] [Port] [Sync Folder] [--compress]\n", argv[0]);
        return EXIT_FAILURE;
    } else if (argc >= 4) {
        ip = argv[1];
        port = atoi(argv[2]);
        base_path = argv[3];
        
        fprintf(stdout, "[INFO] Using IP: %s, Port: %d, Sync Folder: %s\n", ip, port, base_path);

        // Handle compression option
        if (argc == 5) {
            // fprintf(stdout, "[INFO] Checking compression option: %s\n", argv[4]);

            if (strcmp(argv[4], "--compress") == 0 || strcmp(argv[4], "--compress=gzip") == 0) {
                use_compression = 1;
                fprintf(stdout, "[INFO] Compression enabled (gzip)\n");
            } else {
                fprintf(stderr, "[ERROR] Invalid compression option\n");
                return EXIT_FAILURE;
            }

            // if (strcmp(argv[4], "--no-compress") == 0) {
            //     use_compression = 0;
            //     fprintf(stdout, "[INFO] Compression disabled\n");
            // } else if (strncmp(argv[4], "--compress=", 11) == 0) {
            //     const char *type = argv[4] + 11;
            //     if (strcmp(type, "gzip") == 0) {
            //         use_compression = 1;
            //         fprintf(stdout, "[INFO] Compression set to gzip\n");
            //     } else if (strcmp(type, "bz2") == 0) {
            //         use_compression = 2;
            //         fprintf(stdout, "[INFO] Compression set to bz2\n");
            //     } else {
            //         fprintf(stderr, "[ERROR] Invalid compression type: %s\n", type);
            //         return EXIT_FAILURE;
            //     }
            // }
        } else {
            fprintf(stdout, "[INFO] Compression disabled\n");
        }

    } else {
        fprintf(stdout, "[INFO] Using default values - IP: %s, Port: %d, Sync Folder: %s\n", ip, port, base_path);
    }

    // Build complete sync and sent folder paths
    char sync_folder[1024];
    char sent_folder[1024];
    snprintf(sync_folder, sizeof(sync_folder), "%s/to-send", base_path);
    snprintf(sent_folder, sizeof(sent_folder), "%s/sent", base_path);

    // printf("[INFO] To send files folder: %s\n", sync_folder);
    // printf("[INFO] Sent files folder: %s\n", sent_folder);
    // printf("[INFO] Certificates folder: %s\n", CERTIFICATE_PATH);

    

    // Create 'sent' folder if it doesn't exist
    struct stat st = {0};
    // fprintf(stdout, "[INFO] Checking if 'sent' folder exists\n");
    if (stat(sent_folder, &st) == -1) {
        fprintf(stdout, "[INFO] Creating 'sent' folder\n");
        mkdir(sent_folder, 0700);
    } 
    // else {
    //     fprintf(stdout, "[INFO] 'sent' folder already exists\n");
    // }

    // Check if sync folder exists and if are there files to send
    DIR *d;
    int has_files = 0;
    struct dirent *dir;

    // fprintf(stdout, "[INFO] Opening sync folder: %s\n", sync_folder);
    if ((d = opendir(sync_folder)) == NULL) {
        fprintf(stderr, "[ERROR] Failed to open sync folder: %s\n", sync_folder);
        return EXIT_FAILURE;
    }
    // fprintf(stdout, "[INFO] Sync folder opened successfully\n");

    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
        char filepath[BUFFER_SIZE];

        // Lenght validation to avoid buffer overflow
        if (strlen(dir->d_name) > BUFFER_SIZE - strlen(sync_folder) - 2) {
            fprintf(stderr, "[ERROR] Filename too long: %s/%s\n", sync_folder, dir->d_name);
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", sync_folder, dir->d_name);
        if (is_regular_file(filepath)) {
            has_files = 1;
            break;  // Found at least a file, break
        }
    }
    closedir(d);

    if (!has_files) {
        fprintf(stdout, "[INFO] No files to send in folder: %s\n", sync_folder);
        fprintf(stdout, "[INFO] Program completed without connecting to server\n");
        return EXIT_SUCCESS;
    }

    // If there are files to send, proceed to connect
    // Configurazione socket TCP
    int sock;
    struct sockaddr_in serv_addr;
    fprintf(stdout, "[INFO] Creating TCP socket\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "[ERROR] Socket creation failed\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "[INFO] TCP socket created successfully\n");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "[ERROR] Invalid IP address: %s\n", ip);
        close(sock);
        return EXIT_FAILURE;
    }

    // Connessione al server
    int timeout_sec = 10;  // Timeout di 10 secondi (modificabile)
    fprintf(stdout, "[INFO] Connecting to server at %s:%d with timeout %d seconds\n", ip, port, timeout_sec);
    if (connect_with_timeout(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr), timeout_sec) < 0) {
        fprintf(stderr, "[ERROR] Connection to server timed out or failed\n");
        close(sock);
        return EXIT_FAILURE;
    }
    fprintf(stdout, "[INFO] Connected to server successfully\n");

    // Configurazione SSL
    fprintf(stdout, "[INFO] Initializing OpenSSL\n");
    init_openssl();
    fprintf(stdout, "[INFO] Creating SSL context\n");
    ssl_ctx = create_ssl_context();
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);

    // Handshake SSL/TLS
    fprintf(stdout, "[INFO] Performing SSL/TLS handshake\n");
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[ERROR] SSL/TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }
    fprintf(stdout, "[INFO] SSL/TLS handshake completed successfully\n");

    // Verifica certificato server
    fprintf(stdout, "[INFO] Verifying server certificate\n");
    X509 *cert = SSL_get_peer_certificate(ssl);
    long verify_result = SSL_get_verify_result(ssl);
    if (!cert || verify_result != X509_V_OK) {
        fprintf(stderr, "[ERROR] Server certificate verification failed\n");
        print_ssl_error(ssl, verify_result);
        if (cert) X509_free(cert);
        SSL_shutdown(ssl);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }
    X509_free(cert);
    fprintf(stdout, "[INFO] Server certificate verified successfully\n");

    // Elaborazione file nella cartella specificata
    fprintf(stdout, "[INFO] Reopening sync folder: %s\n", sync_folder);
    if ((d = opendir(sync_folder)) == NULL) {
        fprintf(stderr, "[ERROR] Failed to reopen sync folder: %s\n", sync_folder);
        SSL_shutdown(ssl);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    // Ciclo di elaborazione file
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;

        char filepath[BUFFER_SIZE];

        // Lenght validation to avoid buffer overflow
        if (strlen(dir->d_name) > BUFFER_SIZE - strlen(sync_folder) - 2) {
            fprintf(stderr, "[ERROR] Filename too long: %s/%s\n", sync_folder, dir->d_name);
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", sync_folder, dir->d_name);

        if (is_regular_file(filepath)) {
            fprintf(stdout, "[INFO] Processing file: %s\n", filepath);
            char compressed_filename[BUFFER_SIZE];
            char *send_filename;

            if (use_compression > 0) {
                snprintf(compressed_filename, sizeof(compressed_filename), "%s.gz", filepath);
                fprintf(stdout, "[INFO] Compressing file with gzip to: %s\n", compressed_filename);
                compress_file(filepath, compressed_filename, use_compression);
                send_filename = compressed_filename;
            } else {
                send_filename = filepath;
            }

            fprintf(stdout, "[INFO] Sending file: %s\n", send_filename);
            if (send_file(ssl, send_filename)) {
                fprintf(stderr, "[ERROR] Failed to send file: %s\n", send_filename);
                if (use_compression > 0) {
                    remove(compressed_filename); // Remove compressed file on error
                }
                continue; // Skip to next file
            } else {
                fprintf(stdout, "[INFO] File %s sent successfully\n", send_filename);
            }

            if (use_compression > 0) {
                remove(compressed_filename);
                // fprintf(stdout, "[INFO] Temporary compressed file removed\n");
            }

            fprintf(stdout, "[INFO] Moving file to 'sent' folder\n");
            move_file_to_sent(filepath,sent_folder);
            fprintf(stdout, "[INFO] File %s processed successfully\n", filepath);
        }
    }
    closedir(d);
    fprintf(stdout, "[INFO] All files processed, closing sync folder\n");

    // Chiusura connessione SSL
    fprintf(stdout, "[INFO] Shutting down SSL connection\n");
    int shutdown_ret;
    do {
        shutdown_ret = SSL_shutdown(ssl);
    } while (shutdown_ret == 0);
    fprintf(stdout, "[INFO] SSL connection shut down successfully\n");

    // Pulizia risorse
    fprintf(stdout, "[INFO] Freeing SSL resources\n");
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    fprintf(stdout, "[INFO] All resources freed\n");

    fprintf(stdout, "[INFO] Program completed successfully\n");
    return EXIT_SUCCESS;
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
    
    // Controlla la data di scadenza
    int rc = X509_cmp_current_time(not_after);
    if (rc == 0) {
        fprintf(stderr, "[CERT ERROR] Invalid expiration time format\n");
    } else if (rc < 0) {
        fprintf(stderr, "[CERT ERROR] Certificate expired\n");
    } else {
        // Calcola il tempo rimanente prima della scadenza
        if (ASN1_TIME_diff(&days_remaining, &seconds_remaining, NULL, not_after)) {
            fprintf(stdout, "[INFO] Certificate expires in %d days and %d seconds\n", 
                    days_remaining, seconds_remaining);
        } else {
            fprintf(stderr, "[ERROR] Failed to calculate time difference for certificate expiration\n");
        }
    }
    
    // Controlla la data di attivazione
    rc = X509_cmp_current_time(not_before);
    if (rc == 0) {
        fprintf(stderr, "[CERT ERROR] Invalid activation time format\n");
    } else if (rc > 0) {
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
 
 /* Invia un file attraverso la connessione SSL */
int send_file(SSL *ssl, const char *filename) {

    size_t filesize = get_file_size(filename);
    char *header_buffer = NULL;

    // Create metadata header
    uint8_t filename_len = strlen(filename);
    if (strlen(filename) > 255) {
        fprintf(stderr, "[ERROR] Filename is too long (max 255 bytes).\n");
        return -1;
    }

    // Allocate memory for the header buffer
    uint32_t message_len = 1 + filename_len + 8;
    size_t header_size = 4 + message_len;
    header_buffer = (char*)malloc(header_size);
    if (header_buffer == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate %zx bytes of memory for header.\n", header_size);
        return -1;
    }

    // --- Pack the data into the buffer ---
    char* ptr = header_buffer;
    uint32_t message_len_be = htonl(message_len); // Host To Network Long
    memcpy(ptr, &message_len_be, 4);
    ptr += 4;

    *ptr = filename_len;    // Length of the filename (1 byte)
    ptr++;

    memcpy(ptr, filename, filename_len);    // Copy the filename into the buffer
    ptr += filename_len;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint64_t file_size_be = __builtin_bswap64(filesize);
#else
    uint64_t file_size_be = filesize;
#endif
    memcpy(ptr, &file_size_be, 8);  // Copy the file size into the buffer

    fprintf(stdout, "[INFO] Sending metadata for file: %s (size: %lu bytes)\n", filename, filesize);
    if (SSL_write(ssl, header_buffer, header_size) <= 0) {
        fprintf(stderr, "[ERROR] Failed to send metadata for %s\n", filename);
        return -1;
        // exit(EXIT_FAILURE);
    }
    fprintf(stdout, "[INFO] Metadata sent successfully\n");

    char ack[2] = {0};
    int ret = SSL_read(ssl, ack, 2);

    if (ret <= 0 || strcmp(ack, "a") != 0) {
        fprintf(stderr, "[ERROR] Metadata ACK failed for %s\n", filename);
        return -2;
    }
    fprintf(stdout, "[INFO] Metadata ACK received: %s\n", ack);

    char buffer[BUFFER_SIZE] = {0};
    const size_t LOG_INTERVAL = 1 * 1024 * 1024; // 1 MB in byte
    size_t last_logged = 0; // Ultimo punto in cui è stato stampato un messaggio

    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Failed to open file: %s\n", filename);
        return -3;
        // exit(EXIT_FAILURE);
    }
    fprintf(stdout, "[INFO] File %s opened for sending\n", filename);

    size_t bytes_sent = 0;
    while (bytes_sent < filesize) {
        size_t to_read = (filesize - bytes_sent) < BUFFER_SIZE ? (filesize - bytes_sent) : BUFFER_SIZE;
        size_t read_bytes = fread(buffer, 1, to_read, file);
        if (read_bytes > 0) {
            int sent = SSL_write(ssl, buffer, read_bytes);
            if (sent <= 0) {
                fprintf(stderr, "[ERROR] SSL write error while sending %s\n", filename);
                fclose(file);
                return -4;
            }
            bytes_sent += sent;

            // Stampa solo ogni 1 MB o alla fine del file
            if (bytes_sent - last_logged >= LOG_INTERVAL || bytes_sent == filesize) {
                fprintf(stdout, "[INFO] Sent %lu bytes of %s (total: %lu/%lu)\n", 
                        bytes_sent - last_logged, filename, bytes_sent, filesize);
                last_logged = bytes_sent;
            }
        }
    }
    fclose(file);
    fprintf(stdout, "[INFO] File %s sent successfully\n", filename);

    char end_ack[2] = {0};
    int read_ret = SSL_read(ssl, end_ack, 2);
    if (read_ret <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive end ACK for %s\n", filename);
        ERR_print_errors_fp(stderr);
        return -5;
    } else {
        fprintf(stdout, "[INFO] End ACK received: %s\n", end_ack);
    }

    return 0;
}
 
 /* Funzione per la compressione dei file */
 void compress_file(const char *input_file, const char *output_file, int compression_type) {
    fprintf(stdout, "[INFO] Starting compression of %s to %s\n", input_file, output_file);

    FILE *source = fopen(input_file, "rb");
    if (!source) {
        fprintf(stderr, "[ERROR] Failed to open input file: %s\n", input_file);
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "[INFO] Input file %s opened\n", input_file);

    if (compression_type == 1) {
        gzFile dest = gzopen(output_file, GZIP_COMPRESSION_MODE); 
        if (!dest) {
            fprintf(stderr, "[ERROR] Failed to open gzip output file: %s\n", output_file);
            fclose(source);
            exit(EXIT_FAILURE);
        }
        fprintf(stdout, "[INFO] Gzip output file %s opened\n", output_file);

        char buffer[BUFFER_SIZE];
        int bytes_read;
        while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, source)) > 0) {
            if (gzwrite(dest, buffer, bytes_read) != bytes_read) {
                fprintf(stderr, "[ERROR] Failed to write compressed data to %s\n", output_file);
                fclose(source);
                gzclose(dest);
                exit(EXIT_FAILURE);
            }
        }
        gzclose(dest);
        fprintf(stdout, "[INFO] Gzip compression completed for %s\n", output_file);
    } 
    // else if (compression_type == 2) {  // BZIP2
    //     FILE *dest = fopen(output_file, "wb");
    //     if (!dest) {
    //         fprintf(stderr, "[ERROR] Failed to open bz2 output file: %s\n", output_file);
    //         fclose(source);
    //         exit(EXIT_FAILURE);
    //     }
    //     BZFILE *bz2 = BZ2_bzWriteOpen(NULL, dest, 9, 0, 0);
    //     if (!bz2) {
    //         fprintf(stderr, "[ERROR] Failed to initialize bz2 compression for %s\n", output_file);
    //         fclose(source);
    //         fclose(dest);
    //         exit(EXIT_FAILURE);
    //     }
    //     fprintf(stdout, "[INFO] Bz2 output file %s opened\n", output_file);

    //     char buffer[BUFFER_SIZE];
    //     int bytes_read;
    //     while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, source)) > 0) {
    //         BZ2_bzWrite(NULL, bz2, buffer, bytes_read);
    //     }
    //     BZ2_bzWriteClose(NULL, bz2, 0, NULL, NULL);
    //     fclose(dest);
    //     fprintf(stdout, "[INFO] Bz2 compression completed for %s\n", output_file);
    // }

    fclose(source);
    fprintf(stdout, "[INFO] Compression process finished\n");
}
 
 /* Ottiene la dimensione del file in byte */
 size_t get_file_size(const char *filename) {
     struct stat st;
     if (stat(filename, &st) == 0) {
         return st.st_size;
     }
     fprintf(stderr,"Failed to get file size\n");
     exit(EXIT_FAILURE);
 }
 
 /* Verifica se il path è un file regolare */
 int is_regular_file(const char *path) {
     struct stat st;
     return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
 }
 
 /* Sposta il file nella cartella 'sent' */
 void move_file_to_sent(const char *filepath,const char *sent_folder) {
    fprintf(stdout, "[INFO] Preparing to move file: %s\n", filepath);

    if (!filepath || strlen(filepath) == 0) {
        fprintf(stderr, "[ERROR] Invalid filepath\n");
        return;
    }

    struct stat st;
    if (stat(filepath, &st) != 0) {
        fprintf(stderr, "[ERROR] File %s not found, skipping move\n", filepath);
        return;
    }

    const char *filename = strrchr(filepath, '/');
    if (filename) {
        filename++;
    } else {
        filename = filepath;
    }

    char new_filepath[BUFFER_SIZE];

    snprintf(new_filepath, sizeof(new_filepath), "%s/%s", sent_folder, filename);
    fprintf(stdout, "[INFO] Moving %s to %s\n", filepath, new_filepath);

    if (rename(filepath, new_filepath) == 0) {
        fprintf(stdout, "[INFO] File moved successfully to: %s\n", new_filepath);
    } else {
        fprintf(stderr, "[ERROR] Failed to move file %s\n", filepath);
    }
}
 
 /* Inizializza le librerie OpenSSL */
 void init_openssl() {
    SSL_load_error_strings();   // Carica i messaggi di errore SSL
    OpenSSL_add_ssl_algorithms(); // Inizializza gli algoritmi crittografici
    OpenSSL_add_all_algorithms(); 
    ERR_load_crypto_strings();     
 }
 
 /* Crea e configura il contesto SSL per il client */
 SSL_CTX *create_ssl_context() {
     const SSL_METHOD *method = SSLv23_client_method();  // Dobbiamo usare questo perche in centralina c'è openssl 1.0.2
     SSL_CTX *ctx = SSL_CTX_new(method);
     
     if (!ctx) {
         fprintf(stderr,"Unable to create SSL context");
         ERR_print_errors_fp(stderr);
         exit(EXIT_FAILURE);
     }

     SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
 
     // Load client cert and key
    //  fprintf(stdout, "[DEBUG] Tentativo di caricare il certificato del client da: %s\n", CLIENT_CERT_PATH);
     if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_PATH, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr,"Unable to load SSL certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
     }
     
    //  fprintf(stdout, "[DEBUG] Tentativo di caricare la chiave privata del client da: %s\n", CLIENT_KEY_PATH);
     if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_PATH, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr,"Unable to load SSL key client");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
     }
 
     // Configura la verifica del certificato server
     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    //  fprintf(stdout, "[DEBUG] Tentativo di caricare il certificato CA per la verifica del server da: %s\n", CA_CERT_PATH);
     if (SSL_CTX_load_verify_locations(ctx, CA_CERT_PATH, NULL) <= 0) {
        fprintf(stderr, "Unable to load CA certificate from %s\n", CA_CERT_PATH);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
     return ctx;
 }
 
 /* Pulizia risorse OpenSSL */
 void cleanup_openssl() {
    EVP_cleanup();  // Dealloca gli algoritmi caricati
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
 }
 
 // Funzione per eseguire una connect() con timeout
int connect_with_timeout(int sock, const struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    // Imposta la socket in modalità non bloccante
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int res = connect(sock, addr, addrlen);
    if (res < 0) {
        if (errno != EINPROGRESS) {
            return -1; // Errore immediato
        }
    }

    if (res == 0) {
        // Connessione completata immediatamente
        fcntl(sock, F_SETFL, flags); // Ripristina la modalità bloccante
        return 0;
    }

    // Attende che la socket diventi scrivibile (cioè la connect() sia completata)
    fd_set wait_set;
    FD_ZERO(&wait_set);
    FD_SET(sock, &wait_set);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    res = select(sock + 1, NULL, &wait_set, NULL, &tv);
    if (res <= 0) {
        // Timeout o errore
        return -1;
    }

    // Verifica se ci sono errori sulla socket
    int so_error;
    socklen_t len = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        return -1;
    }
    if (so_error != 0) {
        errno = so_error;
        return -1;
    }

    // Ripristina la modalità bloccante originale
    fcntl(sock, F_SETFL, flags);
    return 0;
}