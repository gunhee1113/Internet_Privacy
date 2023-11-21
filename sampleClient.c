#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>
#include <curl/curl.h>

// TODO: Callback function for custom certificate verification
int valid = 1;

int verify_func(int preverify_ok, X509_STORE_CTX *ctx){
    int err;
    X509 *err_cert;
    char buf[256];
    
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
    if (!preverify_ok) {
        valid = 0;
        printf("Verification Error: %s\n",  X509_verify_cert_error_string(err));
        printf("Subject:%s\n", buf);
        if(err == X509_V_ERR_CERT_HAS_EXPIRED){
            ASN1_TIME *time = X509_get_notAfter(err_cert);
            BIO* b = BIO_new_fp(stdout, BIO_NOCLOSE);
            printf("Expired time : ");
            ASN1_TIME_print(b, time);
            BIO_free(b);
            printf("\n\n");
        }
    }
    return 1;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    FILE *fp = (FILE *)userp;
    size_t written = fwrite(contents, size, nmemb, fp);
    return written;
}

int download_crl(const char *crl_url, const char *output_file) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error initializing libcurl\n");
        return -1;
    }

    FILE *output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error opening output file\n");
        curl_easy_cleanup(curl);
        return -1;
    }

    // Set the URL
    curl_easy_setopt(curl, CURLOPT_URL, crl_url);

    // Set the write callback function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, output_fp);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Error downloading CRL: %s\n", curl_easy_strerror(res));
        fclose(output_fp);
        curl_easy_cleanup(curl);
        return -1;
    }

    // Clean up
    fclose(output_fp);
    curl_easy_cleanup(curl);

    return 0;
}


void print_certificate(X509 *cert) {
    if (cert) {
        printf("Certificate:\n");
        X509_print_fp(stdout, cert);
        printf("\n");
    }
}

void print_certificate_info(X509 *cert, int depth) {
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME *issuer = X509_get_issuer_name(cert);

    char subj_str[256];
    char issuer_str[256];

    // Convert the names to a readable string
    X509_NAME_oneline(subj, subj_str, sizeof(subj_str));
    X509_NAME_oneline(issuer, issuer_str, sizeof(issuer_str));

    // Print the certificate details at the given depth
    printf("Certificate at depth: %d\n", depth);
    printf("Subject: %s\n", subj_str);
    printf("Issuer: %s\n\n", issuer_str);
}

void save_certificate(X509 *cert, const char *filename) {
    if (cert) {
        FILE *fp = fopen(filename, "w");
        if (fp) {
            PEM_write_X509(fp, cert);
            fclose(fp);
            printf("Saved certificate to %s\n", filename);
        } else {
            fprintf(stderr, "Could not open %s for writing.\n", filename);
        }
    }
}

X509_CRL *load_crl(const char *crl_filestr, BIO *outbio) {
    BIO *crlbio = BIO_new(BIO_s_file());
    if (BIO_read_filename(crlbio, crl_filestr) <= 0) {
        BIO_printf(outbio, "Error loading CRL into memory\n");
        return NULL;
    }

    X509_CRL *mycrl = d2i_X509_CRL_bio(crlbio, NULL);

    if (!mycrl) {
        BIO_printf(outbio, "Error reading CRL from BIO\n");
    }

    BIO_free_all(crlbio);

    return mycrl;
}


int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    X509 *cert;
    STACK_OF(X509) *cert_chain;
    int option;
    int verbose = 0, output_files = 0;

    while ((option = getopt(argc, argv, "vo")) != -1) {
        switch (option) {
            case 'v': verbose = 1; break;
            case 'o': output_files = 1; break;
            default: fprintf(stderr, "Invalid option\n");
                     exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-v|-o] <host>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *host = argv[optind];

    // Initialize OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // TODO: Set the location of the trust store. Currently based on Debian.
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Error setting up trust store.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // TODO: automatic chain verification should be modified
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_func);


    // Create a new BIO chain with an SSL BIO using the context
    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set up the SSL
    BIO_get_ssl(bio, &ssl);
    if (ssl == NULL) {
        fprintf(stderr, "Error getting SSL.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set the SNI hostname
    SSL_set_tlsext_host_name(ssl, host);

    // Set up the connection to the remote host
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_port(bio, "443");

    // Enable OCSP stapling
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

    // Attempt to connect
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to remote host.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Attempt to do the TLS/SSL handshake
    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    long verification_result = SSL_get_verify_result(ssl);
    if (verification_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %ld (%s)\n",
                verification_result, X509_verify_cert_error_string(verification_result));
    }

    // Check for stapled OCSP response
    const unsigned char *ocsp_resp;
    long ocsp_resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_resp);
    OCSP_RESPONSE *response = NULL;

    if (ocsp_resp_len > 0) {
        printf("OCSP response is stapled.\n");
        
        // Decode the OCSP response
        const unsigned char *p = ocsp_resp; // temporary pointer
        response = d2i_OCSP_RESPONSE(NULL, &p, ocsp_resp_len);
        if (response) {
            if (verbose) {
                OCSP_RESPONSE_print(BIO_new_fp(stdout, BIO_NOCLOSE), response, 0);
            }
            
            if (output_files) {
                // Save the OCSP response to a file
                FILE *fp = fopen("ocsp.pem", "wb");
                if (fp != NULL) {
                    const int length = i2d_OCSP_RESPONSE(response, NULL);
                    if (length > 0) {
                        unsigned char *der = malloc(length);
                        unsigned char *p = der;
                        if (i2d_OCSP_RESPONSE(response, &p) > 0) {
                            fwrite(der, 1, length, fp);
                            printf("OCSP response saved to ocsp.pem\n");
                        } else {
                            fprintf(stderr, "Error converting OCSP response to DER format.\n");
                        }
                        free(der);
                    } else {
                        fprintf(stderr, "Error determining OCSP response length.\n");
                    }
                    fclose(fp);
                } else {
                    fprintf(stderr, "Unable to open ocsp.pem for writing.\n");
                }
            }
            OCSP_RESPONSE_free(response);
        } else {
            fprintf(stderr, "Failed to decode OCSP response.\n");
        }
    } else {
        printf("No OCSP stapling response received.\n");
    }

    // Get the certificate chain
    cert_chain = SSL_get_peer_cert_chain(ssl);
    if (cert_chain == NULL) {
        fprintf(stderr, "Error getting certificate chain.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Print details for each certificate in the chain
    for (int i = 0; i < sk_X509_num(cert_chain); i++) {
        cert = sk_X509_value(cert_chain, i);
        if (verbose) {
            print_certificate(cert);
        } else {
        // For non-verbose, print simplified information
        print_certificate_info(cert, i);
        }
        if (output_files) {
            char filename[32];
            snprintf(filename, sizeof(filename), "depth%d.pem", i);
            save_certificate(cert, filename);
        }
        // TODO: Get CRL distribution points and OCSP responder URI
        STACK_OF(DIST_POINT) *crldp_stack = NULL;
        crldp_stack = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
        
        if (crldp_stack) {
            printf("CRL Distribution Points:\n");
            
            for (int j = 0; j < sk_DIST_POINT_num(crldp_stack); j++) {
                DIST_POINT *point = sk_DIST_POINT_value(crldp_stack, j);
                GENERAL_NAMES *names = point->distpoint->name.fullname;

                for (int k = 0; k < sk_GENERAL_NAME_num(names); k++) {
                    GENERAL_NAME *name = sk_GENERAL_NAME_value(names, k);

                    if (name->type == GEN_URI) {
                        char *uri = (char *)ASN1_STRING_get0_data(name->d.ia5);
                        printf("URI: %s\n", uri);
                        if(i==0){
                            download_crl(uri, "crl_file.pem");
                        }
                    }
                }
            }

            sk_DIST_POINT_pop_free(crldp_stack, DIST_POINT_free);
        } 
        else {
            printf("No CRL Distribution Points extension found.\n");
        }

        STACK_OF(ACCESS_DESCRIPTION) *ocsp_stack = NULL;
        ocsp_stack = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

        if (ocsp_stack) {
            printf("OCSP Responder URIs:\n");

            for (int j = 0; j < sk_ACCESS_DESCRIPTION_num(ocsp_stack); j++) {
                ACCESS_DESCRIPTION *desc = sk_ACCESS_DESCRIPTION_value(ocsp_stack, j);

                if (OBJ_obj2nid(desc->method) == NID_ad_OCSP) {
                    GENERAL_NAME *location = desc->location;

                    if (location->type == GEN_URI) {
                        char *uri = (char *)ASN1_STRING_get0_data(location->d.ia5);
                        printf("URI: %s\n", uri);
                    }
                }
            }

            sk_ACCESS_DESCRIPTION_pop_free(ocsp_stack, ACCESS_DESCRIPTION_free);
        } else {
            printf("No OCSP Responder extension found.\n");
        }
        printf("\n");
    }
    // Revocation checking
    if(valid){
        printf("Revocation checking...\n");
        BIO *bio_r;
        bio_r = BIO_new_file("./crl_file.pem", "r");
        X509_CRL *crl;
        crl = load_crl("crl_file.pem", bio_r);
        if (crl == NULL) {
            fprintf(stderr, "Error reading CRL from file.\n");
            ERR_print_errors_fp(stderr);
            BIO_free(bio_r);
        }
        X509_STORE *store = X509_STORE_new();
        X509_STORE_add_crl(store, crl);
        X509* leaf_cert = sk_X509_value(cert_chain, 0);
        X509_STORE_CTX *ctx_r = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx_r, store, leaf_cert, cert_chain);
        X509_REVOKED *revoked = NULL;
        int result = X509_CRL_get0_by_cert(crl, &revoked, leaf_cert);

        if (result == 1 && revoked != NULL) {
            printf("Certificate is revoked (CRL check passed)\n");
            // Get the revocation time
            const ASN1_TIME *revocation_time = X509_REVOKED_get0_revocationDate(revoked);
            bio_r = BIO_new(BIO_s_mem());
            ASN1_TIME_print(bio_r, revocation_time);
            char buffer[1024];
            BIO_read(bio_r, buffer, sizeof(buffer) - 1);
            buffer[sizeof(buffer) - 1] = '\0';
            printf("Revoked Time: %s\n", buffer);
        } 
        else if(revoked == NULL){
            printf("Certificate is not revoked\n");   
        }
        else{
            printf("CRL check failed: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx_r)));
        }

        // Free the resources
        BIO_free(bio_r);
        X509_CRL_free(crl);
        X509_STORE_CTX_free(ctx_r);
    }


    // Clean up
    ERR_clear_error();
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
