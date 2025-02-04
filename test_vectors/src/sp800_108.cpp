#include <botan/kdf.h>
#include <botan/build.h>
#include <assert.h>
#include <iostream>
#include <iomanip>

using namespace std;

/*
 * Generate test vectors for SP 800-108 using the Botan library.
 *
 * Input key: 16 bytes
 * PRF: HMAC-256, HMAC-384, HMAC-512
 * Label: empty, 1 byte, 2 bytes, 16 bytes
 * Context: empty, 1 byte, 2 bytes, 16 bytes
 */

void print_hex(const char *prefix, const uint8_t *s, size_t slen)
{
    printf("%s", prefix);
    for (unsigned i=0; i<slen; i++) {
        printf("%02X", s[i]);
    }
    printf("\n");
}

void make_tv(Botan::KDF *kdf, const char *label, const char *context, unsigned olen, unsigned count)
{
    uint8_t *out = new uint8_t[olen];
    uint8_t secret[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    kdf->kdf(out, olen,
             secret, 16,
             (uint8_t*)context, strlen(context),
             (uint8_t*)label, strlen(label));

    printf("COUNT = %d\n", count);
    print_hex("KIN = ", secret, sizeof(secret));
    print_hex("LABEL = ", (const uint8_t*)label, strlen(label));
    print_hex("CONTEXT = ", (const uint8_t*)context, strlen(context));
    printf("RLEN = 32\n");
    print_hex("KOUT = ", out, olen);

    printf("\n");
    delete out;
}

int main(void)
{
    typedef struct PRF {
        const char* botan;
        const char* desc;
    } PRF;

    PRF prf[] = {
        { "SP800-108-Counter(HMAC(SHA-256))", "HMAC-SHA-256" },
        { "SP800-108-Counter(HMAC(SHA-384))", "HMAC-SHA-384" },
        { "SP800-108-Counter(HMAC(SHA-512))", "HMAC-SHA-512" },
        { "SP800-108-Counter(CMAC(AES-128))", "CMAC-AES-128" },
        { NULL, NULL }
    };

    const char *text[] = {
        "",
        "A",
        "AB",
        "ABCDEFGHILMNOPQR",
        NULL
    };

    const unsigned olens[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129 };

    unsigned count = 0;

    printf("#\n");
    printf("# Test vectors for NIST SP-800 108, KDF in Counter mode\n");
    printf("# Generated with Botan v%d.%d.%d\n", BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);
    printf("#\n");

    for (PRF *pprf=prf; pprf->botan; pprf++) {
        Botan::KDF *kdf = Botan::get_kdf(pprf->botan);

        assert(kdf);
        printf("\n[%s]\n\n", pprf->desc);

        for (const char **label=text; *label; label++) {
            for (const char **context=text; *context; context++) {
                for (unsigned i=0; i<sizeof(olens)/sizeof(olens[0]); i++) {
                    make_tv(kdf, *label, *context, olens[i], count);
                    count++;
                }
            }
        }
        delete kdf;
    }

    return 0;
}
