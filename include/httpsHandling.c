#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 4433 // Use 443 if running as root

#include "httpsHandling.h"

void initOpenssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanupOpenssl() { EVP_cleanup(); }

SSL_CTX *createContext()
{
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if(!ctx)
	{
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

int configureContext(SSL_CTX *ctx, char* cert_file, char* key_file)
{
	const char* function_name = "configureContext";
	if(cert_file == NULL)
	{
		if(SSL_CTX_use_certificate_file(ctx, DEFAULT_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
		{
			perror(function_name);
			return -1;
		}
	}
	else
	{
		if(SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
		{
			perror(function_name);
			return -1;
		}
	}
	if(cert_file == NULL)
	{
		if(SSL_CTX_use_PrivateKey_file(ctx, DEFAULT_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
		{
			perror(function_name);
			return -1;
		}
	}
	else
	{
		if(SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
		{
			perror(function_name);
			return -1;
		}
	}

	return 0;
}
