#!/bin/sh

set -e
set -x

openssl version | tee openssl_version.txt

# Private key
openssl ecparam -name secp256k1 -genkey -noout -conv_form uncompressed -out ecc_secp256k1_private.pem
openssl ec -in ecc_secp256k1_private.pem -outform DER -out ecc_secp256k1_private.der
openssl pkcs8 -in ecc_secp256k1_private.der -inform DER -out ecc_secp256k1_private_p8_clear.der -outform DER -nocrypt -topk8
openssl pkcs8 -in ecc_secp256k1_private.der -inform DER -out ecc_secp256k1_private_p8_clear.pem -outform PEM -nocrypt -topk8
openssl ec -in ecc_secp256k1_private.pem -text -out ecc_secp256k1.txt

# Encrypted private key
openssl pkcs8 -in ecc_secp256k1_private.der -inform DER -passout 'pass:secret' -out ecc_secp256k1_private_p8.der -outform DER -topk8
openssl pkcs8 -in ecc_secp256k1_private.der -inform DER -passout 'pass:secret' -out ecc_secp256k1_private_p8.pem -outform PEM -topk8
openssl pkcs8 -in ecc_secp256k1_private.der -inform DER -passout 'pass:secret' -out ecc_secp256k1_private_p8_2.der -outform DER -topk8 -iter 12345 -v2 aes256 -v2prf hmacWithSHA512
openssl ec -in ecc_secp256k1_private.pem -aes256 -out ecc_secp256k1_private_enc_aes256.pem -passout 'pass:secret' -outform PEM

# Public key
openssl ec -in ecc_secp256k1_private.pem -pubout -out ecc_secp256k1_public.pem
openssl ec -pubin -in ecc_secp256k1_public.pem -outform DER -out ecc_secp256k1_public.der
openssl ec -pubin -in ecc_secp256k1_public.pem -outform DER -conv_form compressed -out ecc_secp256k1_public_compressed.der
openssl ec -pubin -in ecc_secp256k1_public.pem -outform PEM -conv_form compressed -out ecc_secp256k1_public_compressed.pem

# X.509 cert
openssl req -new -key ecc_secp256k1_private.pem -days 365 -x509 -out ecc_secp256k1_x509.pem -subj '/C=GB/CN=example.com'
openssl x509 -in ecc_secp256k1_x509.pem -out ecc_secp256k1_x509.der -outform DER

# Legacy OpenSSL format with ECPARAMs
openssl ecparam -name secp256k1 -genkey -out ecc_secp256k1_private_ecparams.pem

# No OpenSSH files: OpenSSH has no key type for this curve
