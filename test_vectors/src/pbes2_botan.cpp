#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pkcs8.h>
#include <iostream>

#define array_size(arr) (sizeof(arr) / sizeof(*(arr)))

int main() {
    try {
        const std::string schemes[] = {
            "PBE-PKCS5v20(AES-256/GCM,Scrypt)",
            "PBE-PKCS5v20(AES-192/CBC,SHA-256)",
        };
        std::string password = "your_password";

        // Generate an ECC key pair
        Botan::AutoSeeded_RNG rng;
        Botan::EC_Group ec_group("secp256r1");
        Botan::ECDSA_PrivateKey private_key(rng, ec_group);

        for (int i=0; i<array_size(schemes); i++) {

            // Export the private key as PKCS#8 container encrypted with AES256-GCM
            std::string encrypted_private_key =
                Botan::PKCS8::PEM_encode(private_key, rng, password,
                    std::chrono::milliseconds(10), schemes[i]);

            // Print the encrypted private key
            std::cout << "Using scheme: " << schemes[i] << std::endl;
            std::cout << "Encrypted Private Key:\n" << encrypted_private_key << std::endl;
        }

        return 0;
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

