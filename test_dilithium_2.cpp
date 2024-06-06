#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#ifndef DLL_EXPORT
  #ifdef _WIN32
    #define DLL_EXPORT __declspec(dllexport)
  #else
    #define DLL_EXPORT
  #endif
#endif

extern "C" {
  DLL_EXPORT void keygen(const char *public_key_file, const char *private_key_file);
  DLL_EXPORT void sign(const char *message_file, const char *private_key_file, const char *signature_file);
  DLL_EXPORT void verify(const char *message_file, const char *signature_file, const char *public_key_file);
}

void keygen(const char *public_key_file, const char *private_key_file);
void sign(const char *message_file, const char *private_key_file, const char *signature_file);
void verify(const char *message_file, const char *signature_file, const char *public_key_file);

void keygen(const char *public_key_file, const char *private_key_file) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        printf("Failed to initialize Dilithium algorithm.\n");
        exit(1);
    }

    uint8_t *public_key = (uint8_t*)malloc(sig->length_public_key);
    uint8_t *private_key = (uint8_t*)malloc(sig->length_secret_key);
    if (public_key == NULL || private_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for keys\n");
        exit(1);
    }

    OQS_STATUS status = OQS_SIG_keypair(sig, public_key, private_key);
    if (status != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        exit(1);
    }

    // Save public key to file
    FILE *file = fopen(public_key_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", public_key_file);
        exit(1);
    }
    fwrite(public_key, 1, sig->length_public_key, file);
    fclose(file);

    // Save private key to file
    file = fopen(private_key_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", private_key_file);
        exit(1);
    }
    fwrite(private_key, 1, sig->length_secret_key, file);
    fclose(file);

    OQS_MEM_cleanse(public_key, sig->length_public_key);
    OQS_MEM_cleanse(private_key, sig->length_secret_key);
    printf("Keys generated and saved successfully.\n");
    free(public_key);
    free(private_key);
    OQS_SIG_free(sig);
}

void sign(const char *message_file, const char *private_key_file, const char *signature_file) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        fprintf(stderr, "Failed to initialize Dilithium algorithm\n");
        exit(1);
    }

    // Read private key from file
    FILE *file = fopen(private_key_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", private_key_file);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t private_key_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *private_key = (uint8_t*)malloc(private_key_len);
    if (private_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for private key\n");
        exit(1);
    }
    fread(private_key, 1, private_key_len, file);
    fclose(file);

    // Read message from file
    file = fopen(message_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", message_file);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t message_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *message = (uint8_t*)malloc(message_len);
    if (message == NULL) {
        fprintf(stderr, "Failed to allocate memory for message\n");
        exit(1);
    }
    fread(message, 1, message_len, file);
    fclose(file);

    uint8_t *signature = (uint8_t*)malloc(sig->length_signature);
    size_t signature_len;

    OQS_STATUS status = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, private_key);
    if (status != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_sign failed\n");
        exit(1);
    }

    // Save signature to file
    file = fopen(signature_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", signature_file);
        exit(1);
    }
    fwrite(signature, 1, signature_len, file);
    fclose(file);

    OQS_MEM_cleanse(private_key, private_key_len);
    OQS_MEM_cleanse(signature, sig->length_signature);
    printf("Signature generated and saved successfully.\n");
    free(private_key);
    free(message);
    free(signature);
    OQS_SIG_free(sig);
}

void verify(const char *message_file, const char *signature_file, const char *public_key_file) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        fprintf(stderr, "Failed to initialize Dilithium algorithm\n");
        exit(1);
    }

    // Read public key from file
    FILE *file = fopen(public_key_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", public_key_file);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t public_key_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *public_key = (uint8_t*)malloc(public_key_len);
    if (public_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for public key\n");
        exit(1);
    }
    fread(public_key, 1, public_key_len, file);
    fclose(file);

    // Read message from file
    file = fopen(message_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", message_file);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t message_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *message = (uint8_t*)malloc(message_len);
    if (message == NULL) {
        fprintf(stderr, "Failed to allocate memory for message\n");
        exit(1);
    }
    fread(message, 1, message_len, file);
    fclose(file);

    // Read signature from file
    file = fopen(signature_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", signature_file);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t signature_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *signature = (uint8_t*)malloc(signature_len);
    if (signature == NULL) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        exit(1);
    }
    fread(signature, 1, signature_len, file);
    fclose(file);

    OQS_STATUS status = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    if (status == OQS_SUCCESS) {
        printf("Signature is valid.\n");
    } else {
        printf("Signature is NOT valid.\n");
    }

    OQS_MEM_cleanse(public_key, public_key_len);
    OQS_MEM_cleanse(signature, signature_len);
    free(public_key);
    free(message);
    free(signature);
    OQS_SIG_free(sig);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <mode> [options]\n", argv[0]);
        printf("Modes:\n");
        printf("  keygen <public_key_file> <private_key_file>\n");
        printf("  sign <message_file> <private_key_file> <signature_file>\n");
        printf("  verify <message_file> <signature_file> <public_key_file>\n");
        return 1;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "keygen") == 0) {
        if (argc != 4) {
            printf("Usage: %s keygen <public_key_file> <private_key_file>\n", argv[0]);
            return 1;
        }
        keygen(argv[2], argv[3]);
    } else if (strcmp(mode, "sign") == 0) {
        if (argc != 5) {
            printf("Usage: %s sign <message_file> <private_key_file> <signature_file>\n", argv[0]);
            return 1;
        }
        sign(argv[2], argv[3], argv[4]);
    } else if (strcmp(mode, "verify") == 0) {
        if (argc != 5) {
            printf("Usage: %s verify <message_file> <signature_file> <public_key_file>\n", argv[0]);
            return 1;
        }
        verify(argv[2], argv[3], argv[4]);
    } else {
        printf("Invalid mode\n");
        return 1;
    }

    return 0;
}
