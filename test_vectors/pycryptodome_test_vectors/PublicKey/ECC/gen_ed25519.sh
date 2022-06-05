#!/bin/sh

# Note that openssl's ec command does not support ed25519; you must use the (gen)pkey command

set -e
set -x

openssl version | tee openssl_version_ed25519.txt

# Private key (PKCS#8)
openssl genpkey -algorithm ed25519 -outform PEM -out ecc_ed25519_private.pem
openssl pkey -inform PEM -in ecc_ed25519_private.pem -outform DER -out ecc_ed25519_private.der
openssl pkey -in ecc_ed25519_private.pem -text -out ecc_ed25519.txt

# Encrypted private key
# Traditional format (PEM enveloped) is unsupported for ed25519, so we only use encrypted PKCS#8
openssl pkcs8 -in ecc_ed25519_private.der -inform DER -passout 'pass:secret' -out ecc_ed25519_private_p8.der -outform DER -topk8
openssl pkcs8 -in ecc_ed25519_private.der -inform DER -passout 'pass:secret' -out ecc_ed25519_private_p8.pem -outform PEM -topk8
openssl pkey -in ecc_ed25519_private.pem -des3 -out ecc_ed25519_private_enc_des3.pem -passout 'pass:secret' -outform PEM
openssl pkey -in ecc_ed25519_private.pem -aes128 -out ecc_ed25519_private_enc_aes128.pem -passout 'pass:secret' -outform PEM
openssl pkey -in ecc_ed25519_private.pem -aes192 -out ecc_ed25519_private_enc_aes192.pem -passout 'pass:secret' -outform PEM
openssl pkey -in ecc_ed25519_private.pem -aes256 -out ecc_ed25519_private_enc_aes256.pem -passout 'pass:secret' -outform PEM
# GCM is not supported by openssl in this case...
#openssl pkey -in ecc_ed25519_private.pem -aes-256-gcm -out ecc_ed25519_private_enc_aes256_gcm.pem -passout 'pass:secret' -outform PEM

# Public key
openssl pkey -in ecc_ed25519_private.pem -pubout -out ecc_ed25519_public.pem
openssl pkey -pubin -in ecc_ed25519_public.pem -outform DER -out ecc_ed25519_public.der

# X.509 cert
openssl req -new -key ecc_ed25519_private.pem -days 365 -x509 -out ecc_ed25519_x509.pem -subj '/C=GB/CN=example.com'
openssl x509 -in ecc_ed25519_x509.pem -out ecc_ed25519_x509.der -outform DER

# OpenSSH - also the .pem.pub files are created
# Unfortunately, it does not seem possible to reuse ecc_ed25519_private.pem, we need to regenerate
ssh-keygen -t ed25519 -f ecc_ed25519_private_openssh.pem -P "" -C test
mv ecc_ed25519_private_openssh.pem.pub ecc_ed25519_public_openssh.txt
ssh-keygen -t ed25519 -f ecc_ed25519_private_openssh_pwd.pem -P "password" -C test
rm ecc_ed25519_private_openssh_pwd.pem.pub
