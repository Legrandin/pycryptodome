#!/bin/sh

set -e
set -x

openssl version | tee openssl_version.txt

# Private key
openssl genrsa -out rsa2048_private.pem 2048
openssl rsa -in rsa2048_private.pem -out rsa2048_public.pem -pubout
openssl pkcs8 -in rsa2048_private.pem -topk8 -iter 12345 -out rsa2048_private_p8.der -outform DER -v2 aes256 -v2prf hmacWithSHA512 -passout pass:secret

# Private key - PSS
openssl genpkey -algorithm RSA-PSS -out rsa2048_pss_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in rsa2048_pss_private.pem -out rsa2048_pss_public.pem -pubout

# OpenSSH
chmod 600 rsa2048_private.pem
ssh-keygen -f rsa2048_private.pem -y -C comment > rsa2048_public_openssh.txt

ssh-keygen -t rsa -b 2048 -f rsa2048_private_openssh.pem -P "" -C comment
cp -fa rsa2048_private_openssh.pem rsa2048_private_openssh_old.pem
chmod 600 rsa2048_private_openssh_old.pem
ssh-keygen -p -f rsa2048_private_openssh_old.pem -m PEM -N ""

ssh-keygen -t rsa -b 2048 -f rsa2048_private_openssh_pwd.pem -P "password" -C comment
cp -fa rsa2048_private_openssh_pwd.pem rsa2048_private_openssh_pwd_old.pem
chmod 600 rsa2048_private_openssh_pwd_old.pem
ssh-keygen -p -f rsa2048_private_openssh_pwd_old.pem -m PEM -N "" -P "password" -C comment
