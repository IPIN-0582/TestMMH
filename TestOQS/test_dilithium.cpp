#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void save_data_to_file(const char *filename, const uint8_t *data, size_t data_len)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        exit(1);
    }
    fwrite(data, 1, data_len, file);
    fclose(file);
}

uint8_t *read_data_from_file(const char *filename, size_t *data_len)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    *data_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(*data_len);
    if (data == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for data\n");
        exit(1);
    }

    fread(data, 1, *data_len, file);
    fclose(file);

    return data;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <mode> [options]\n", argv[0]);
        printf("Modes:\n");
        printf("  keygen <public_key_file> <private_key_file>\n");
        printf("  sign <message_file> <private_key_file> <signature_file>\n");
        printf("  verify <message_file> <signature_file> <public_key_file>\n");
        return 1;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "keygen") == 0)
    {
        if (argc != 4)
        {
            printf("Usage: %s keygen <public_key_file> <private_key_file>\n", argv[0]);
            return 1;
        }

        const char *public_key_file = argv[2];
        const char *private_key_file = argv[3];

        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        if (sig == NULL)
        {
            printf("Failed to initialize Dilithium algorithm.\n");
            return 1;
        }

        uint8_t *public_key = (uint8_t *)malloc(sig->length_public_key);
        uint8_t *secret_key = (uint8_t *)malloc(sig->length_secret_key);

        if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS)
        {
            printf("Failed to generate key pair.\n");
            return 1;
        }

        save_data_to_file(public_key_file, public_key, sig->length_public_key);
        save_data_to_file(private_key_file, secret_key, sig->length_secret_key);

        printf("Keys generated and saved successfully.\n");

        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
    }
    else if (strcmp(mode, "sign") == 0)
    {
        if (argc != 5)
        {
            printf("Usage: %s sign <message_file> <private_key_file> <signature_file>\n", argv[0]);
            return 1;
        }

        const char *message_file = argv[2];
        const char *private_key_file = argv[3];
        const char *signature_file = argv[4];

        size_t message_len;
        uint8_t *message = read_data_from_file(message_file, &message_len);

        size_t private_key_len;
        uint8_t *private_key = read_data_from_file(private_key_file, &private_key_len);

        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        if (sig == NULL)
        {
            printf("Failed to initialize Dilithium algorithm.\n");
            return 1;
        }

        uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
        size_t signature_len;

        if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, private_key) != OQS_SUCCESS)
        {
            printf("Failed to sign message.\n");
            return 1;
        }

        save_data_to_file(signature_file, signature, signature_len);

        printf("Signature generated and saved successfully.\n");

        OQS_SIG_free(sig);
        free(message);
        free(private_key);
        free(signature);
    }
    else if (strcmp(mode, "verify") == 0)
    {
        if (argc != 5)
        {
            printf("Usage: %s verify <message_file> <signature_file> <public_key_file>\n", argv[0]);
            return 1;
        }

        const char *message_file = argv[2];
        const char *signature_file = argv[3];
        const char *public_key_file = argv[4];

        size_t message_len;
        uint8_t *message = read_data_from_file(message_file, &message_len);

        size_t signature_len;
        uint8_t *signature = read_data_from_file(signature_file, &signature_len);

        size_t public_key_len;
        uint8_t *public_key = read_data_from_file(public_key_file, &public_key_len);

        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        if (sig == NULL)
        {
            printf("Failed to initialize Dilithium algorithm.\n");
            return 1;
        }

        if (OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key) != OQS_SUCCESS)
        {
            printf("Failed to verify signature.\n");
            return 1;
        }

        printf("Signature successfully verified.\n");

        OQS_SIG_free(sig);
        free(message);
        free(signature);
        free(public_key);
    }
    else
    {
        printf("Invalid mode. Use 'keygen', 'sign', or 'verify'.\n");
        return 1;
    }

    return 0;
}
