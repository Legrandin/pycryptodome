#!/bin/sh

set -e
set -x

# Private key
openssl ecparam -name prime256v1 -genkey -noout -conv_form uncompressed -out ecc_p256_private.pem
openssl ec -in ecc_p256_private.pem -outform DER -out ecc_p256_private.der
openssl pkcs8 -in ecc_p256_private.der -inform DER -out ecc_p256_private_p8_clear.der -outform DER -nocrypt -topk8
openssl ec -in ecc_p256_private.pem -text -out ecc_p256.txt

# Encrypted private key
openssl pkcs8 -in ecc_p256_private.der -inform DER -passout 'pass:secret' -out ecc_p256_private_p8.der -outform DER -topk8
openssl ec -in ecc_p256_private.pem -des3 -out ecc_p256_private_enc.pem -passout 'pass:secret' -outform PEM

# Public key
openssl ec -in ecc_p256_private.pem -pubout -out ecc_p256_public.pem
openssl ec -pubin -in ecc_p256_public.pem -outform DER -out ecc_p256_public.der
