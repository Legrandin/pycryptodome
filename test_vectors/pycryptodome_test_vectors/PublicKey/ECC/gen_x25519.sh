#!/bin/sh

set -e
set -x

openssl version | tee openssl_version_x25519.txt

# Private key (PKCS#8)
openssl genpkey -algorithm x25519 -outform PEM -out ecc_x25519_private.pem
openssl pkey -inform PEM -in ecc_x25519_private.pem -outform DER -out ecc_x25519_private.der
openssl pkey -in ecc_x25519_private.pem -text -out ecc_x25519.txt

# Encrypted private key
# Traditional format (PEM enveloped) is unsupported for x25519, so we only use encrypted PKCS#8
openssl pkcs8 -in ecc_x25519_private.der -inform DER -passout 'pass:secret' -out ecc_x25519_private_p8.der -outform DER -topk8
openssl pkcs8 -in ecc_x25519_private.der -inform DER -passout 'pass:secret' -out ecc_x25519_private_p8.pem -outform PEM -topk8
openssl pkcs8 -in ecc_x25519_private.der -inform DER -passout 'pass:secret' -out ecc_x25519_private_p8_2.der -outform DER -topk8 -iter 12345 -v2 aes256 -v2prf hmacWithSHA512
openssl pkey -in ecc_x25519_private.pem -des3 -out ecc_x25519_private_enc_des3.pem -passout 'pass:secret' -outform PEM
openssl pkey -in ecc_x25519_private.pem -aes128 -out ecc_x25519_private_enc_aes128.pem -passout 'pass:secret' -outform PEM
openssl pkey -in ecc_x25519_private.pem -aes192 -out ecc_x25519_private_enc_aes192.pem -passout 'pass:secret' -outform PEM
openssl pkey -in ecc_x25519_private.pem -aes256 -out ecc_x25519_private_enc_aes256.pem -passout 'pass:secret' -outform PEM
# GCM is not supported by openssl in this case...
#openssl pkey -in ecc_x25519_private.pem -aes-256-gcm -out ecc_x25519_private_enc_aes256_gcm.pem -passout 'pass:secret' -outform PEM

# Public key
openssl pkey -in ecc_x25519_private.pem -pubout -out ecc_x25519_public.pem
openssl pkey -pubin -in ecc_x25519_public.pem -outform DER -out ecc_x25519_public.der

# X.509 cert
openssl ecparam -genkey -name prime256v1 -out ecc-p256-key-temp.pem
openssl req -new -x509 -key ecc-p256-key-temp.pem -out ecc-p256-cert-temp.pem -days 365 -subj "/CN=CA"
openssl req -new -key ecc-p256-key-temp.pem -out ecc-p256-temp.csr -subj "/CN=CA"
openssl x509 -req -in ecc-p256-temp.csr -CAkey ecc-p256-key-temp.pem -CA ecc-p256-cert-temp.pem -force_pubkey ecc_x25519_public.pem -out ecc_x25519_x509.pem -subj "/CN=Client"
openssl x509 -in ecc_x25519_x509.pem -out ecc_x25519_x509.der -outform DER
rm -f ecc-p256-key-temp.pem ecc-p256-cert-temp.pem ecc-p256-temp.csr
