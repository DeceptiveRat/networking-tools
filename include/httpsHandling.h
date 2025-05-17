#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 4433 // Use 443 if running as root
#define DEFAULT_CERT_FILE "cert.pem"
#define DEFAULT_KEY_FILE "key.pem"

// open ssl functions
void initOpenssl();
void cleanupOpenssl();
SSL_CTX *createContext();
int configureContext(SSL_CTX *ctx, char* cert_file, char* key_file);
