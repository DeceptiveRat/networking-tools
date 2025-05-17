#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 4433 // Use 443 if running as root

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() { EVP_cleanup(); }

SSL_CTX *create_context()
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

void configure_context(SSL_CTX *ctx)
{
	if(SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
	   SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

int main()
{
	int sock;
	struct sockaddr_in addr;

	init_openssl();
	SSL_CTX *ctx = create_context();
	configure_context(ctx);

	// Set up TCP socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	listen(sock, 1);

	printf("Listening on port %d (HTTPS)...\n", PORT);

	while(1)
	{
		struct sockaddr_in client;
		unsigned int len = sizeof(client);
		int client_sock = accept(sock, (struct sockaddr *)&client, &len);
		printf("Connection from %s\n", inet_ntoa(client.sin_addr));

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client_sock);

		if(SSL_accept(ssl) <= 0)
		{
			ERR_print_errors_fp(stderr);
		}
		else
		{
			char buf[4096];
			int bytes = SSL_read(ssl, buf, sizeof(buf));
			buf[bytes] = 0;
			printf("Received:\n%s\n", buf);

			// Send Discord-like response
			const char *response = "HTTP/1.1 204 No Content\r\n"
								   "Content-Length: 0\r\n"
								   "\r\n";
			SSL_write(ssl, response, strlen(response));
		}

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client_sock);
	}

	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	return 0;
}
