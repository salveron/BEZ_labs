// Authored by Nikita Mortuzaiev (mortunik)

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>


int main(int argc, char * argv []){

    // Establishing the connection to the server
    printf("Establishing the connection...\n");
    int socket_fd = socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);

    struct sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, "2001:718:2:2908::212", server_addr.sin6_addr.s6_addr) != 1){
        perror("Error converting the address.\n"); return 1; }
    server_addr.sin6_port = htons(443);

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0){
        perror("Error connecting to the server.\n"); return 1; }

    // Initializing the SSL library
    printf("Initializing the SSL library...\n");
    SSL_library_init();

    // Creating the context
    printf("Creating the context...\n");
    SSL_CTX * ssl_context = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_context){
        perror("Error creating the context.\n"); return 1; }
    SSL_CTX_set_options(ssl_context, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);

    // Setting the default paths for the trusted certificates
    if (SSL_CTX_set_default_verify_paths(ssl_context) != 1){
        perror("Error setting the default path for the trusted certificates.\n"); return 1; }

    // Creating the SSL struct
    printf("Creating the SSL struct...\n");
    SSL * ssl = SSL_new(ssl_context);
    if (!ssl){
        perror("Error creating the ssl structure.\n"); return 1; }

    if (SSL_set_fd(ssl, socket_fd) != 1){
        perror("Error setting the file descriptor.\n"); return 1; }
    if (SSL_set_tlsext_host_name(ssl, "fit.cvut.cz") != 1){
        perror("Error setting the host name.\n"); return 1; }

    // Restricting the cipher TLS_AES_256_GCM_SHA384 by removing it from the list
    printf("Restricting the %s cipher...\n", "TLS_AES_256_GCM_SHA384");
    if (SSL_CTX_set_ciphersuites(ssl_context, "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1){
        perror("Error restricting the cipher.\n"); return 1; }

    // Printing the client's ciphers
    printf("The ciphers available for the client: ");
    int priority = 0;
    while(1){
        const char * cipher_name = SSL_get_cipher_list(ssl, priority);
        if (cipher_name) printf("%s, ", cipher_name);
        else break;
        priority ++;
    }
    printf("\nSummary: %d ciphers available.\n", priority);

    // Connecting safely
    printf("Establishing the secured connection...\n");
    if (SSL_connect(ssl) != 1){
        perror("Error connecting with ssl.\n"); return 1; }

    // Getting the name of the cipher used for the connection
    const char * connection_cipher_name = SSL_get_cipher_name(ssl);
    printf("The cipher used for the connection: %s.\n", connection_cipher_name);

    /* The default cipher is TLS_AES_256_GCM_SHA384 (restricted above). This cipher would be used for the secure
     * connection after it's established (the data sent between the client and the server would be encrypted with
     * this cipher). The ciphersuites setting above helps to choose another cipher for the secure connection. */

    // Get the certificate
    printf("Getting the certificate...\n");
    X509 * certificate = SSL_get_peer_certificate(ssl);
    if (!certificate) {
        perror("Error getting the certificate.\n"); return 1; }

    // Getting the result of the certificate verification
    printf("Verifying the certificate...\n");
    long verification_result = SSL_get_verify_result(ssl);
    if (verification_result != X509_V_OK){
        perror("Error verifying the certificate.\n"); return 1; }

    // Write the certificate to the file
    printf("Saving the certificate to the file \"certificate.pem\"...\n");
    FILE * cfd = fopen("certificate.pem", "wb");
    if (!cfd) {
        perror("Error opening the certificate output file.\n"); return 1; }
    if (PEM_write_X509(cfd, certificate) != 1){
        perror("Error writing the certificate to the file.\n"); return 1; }

    // Download the page
    const char * buffer = "GET /cs/studium/informacni-servis/rozcestnik-systemu HTTP/1.1\r\n"
                          "Host: fit.cvut.cz\r\n"
                          "Connection: close\r\n"
                          "\r\n";
    size_t buffer_size = strlen(buffer);
    if (SSL_write(ssl, buffer, buffer_size) != buffer_size){
        perror("Error sending the data.\n"); return 1; }

    printf("Downloading the page and saving it to the file \"page.html\"...\n");
    FILE * pfd = fopen("page.html", "w");
    const int rcv_buffer_size = 2048;
    char rcv_buffer [rcv_buffer_size];
    while(1){
        int bytes_received = SSL_read(ssl, rcv_buffer, rcv_buffer_size);
        if (bytes_received == 0) break;
        fwrite(rcv_buffer, sizeof(char), bytes_received, pfd);
    }

    // Clean up
    printf("Cleaning up...\n");
    fclose(pfd);
    fclose(cfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_context);
    return 0;
}
