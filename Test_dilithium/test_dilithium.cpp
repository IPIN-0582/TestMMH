#include <iostream>
#include <fstream>
#include <vector>
#include <oqs/oqs.h>

void print_hex(const std::vector<uint8_t> &data)
{
    for (auto byte : data)
    {
        printf("%02x", byte);
    }
    printf("\n");
}

void save_data_to_file(const std::string &filename, const std::vector<uint8_t> &data)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

std::vector<uint8_t> read_data_from_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    file.seekg(0, std::ios::end);
    size_t length = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(length);
    file.read(reinterpret_cast<char *>(data.data()), length);
    return data;
}

void generate_keypair(const std::string &public_key_file, const std::string &private_key_file)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig)
    {
        throw std::runtime_error("Failed to initialize Dilithium algorithm.");
    }

    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> secret_key(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS)
    {
        OQS_SIG_free(sig);
        throw std::runtime_error("Failed to generate key pair.");
    }

    save_data_to_file(public_key_file, public_key);
    save_data_to_file(private_key_file, secret_key);

    std::cout << "Keys generated and saved successfully.\n";

    OQS_SIG_free(sig);
}

void sign_message(const std::string &message_file, const std::string &private_key_file, const std::string &signature_file)
{
    auto message = read_data_from_file(message_file);
    auto private_key = read_data_from_file(private_key_file);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig)
    {
        throw std::runtime_error("Failed to initialize Dilithium algorithm.");
    }

    std::vector<uint8_t> signature(sig->length_signature);
    size_t signature_len;

    if (OQS_SIG_sign(sig, signature.data(), &signature_len, message.data(), message.size(), private_key.data()) != OQS_SUCCESS)
    {
        OQS_SIG_free(sig);
        throw std::runtime_error("Failed to sign message.");
    }

    signature.resize(signature_len);
    save_data_to_file(signature_file, signature);

    std::cout << "Signature generated and saved successfully.\n";

    OQS_SIG_free(sig);
}

void verify_signature(const std::string &message_file, const std::string &signature_file, const std::string &public_key_file)
{
    auto message = read_data_from_file(message_file);
    auto signature = read_data_from_file(signature_file);
    auto public_key = read_data_from_file(public_key_file);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig)
    {
        throw std::runtime_error("Failed to initialize Dilithium algorithm.");
    }

    if (OQS_SIG_verify(sig, message.data(), message.size(), signature.data(), signature.size(), public_key.data()) != OQS_SUCCESS)
    {
        OQS_SIG_free(sig);
        throw std::runtime_error("Failed to verify signature.");
    }

    std::cout << "Signature successfully verified.\n";

    OQS_SIG_free(sig);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <mode> [options]\n";
        std::cerr << "Modes:\n";
        std::cerr << "  keygen <public_key_file> <private_key_file>\n";
        std::cerr << "  sign <message_file> <private_key_file> <signature_file>\n";
        std::cerr << "  verify <message_file> <signature_file> <public_key_file>\n";
        return 1;
    }

    std::string mode = argv[1];

    try
    {
        if (mode == "keygen")
        {
            if (argc != 4)
            {
                std::cerr << "Usage: " << argv[0] << " keygen <public_key_file> <private_key_file>\n";
                return 1;
            }
            generate_keypair(argv[2], argv[3]);
        }
        else if (mode == "sign")
        {
            if (argc != 5)
            {
                std::cerr << "Usage: " << argv[0] << " sign <message_file> <private_key_file> <signature_file>\n";
                return 1;
            }
            sign_message(argv[2], argv[3], argv[4]);
        }
        else if (mode == "verify")
        {
            if (argc != 5)
            {
                std::cerr << "Usage: " << argv[0] << " verify <message_file> <signature_file> <public_key_file>\n";
                return 1;
            }
            verify_signature(argv[2], argv[3], argv[4]);
        }
        else
        {
            std::cerr << "Invalid mode. Use 'keygen', 'sign', or 'verify'.\n";
            return 1;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }

    return 0;
}
