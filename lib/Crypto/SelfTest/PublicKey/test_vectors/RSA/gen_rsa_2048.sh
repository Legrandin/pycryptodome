#!/bin/sh

set -e
set -x

openssl version | tee openssl_version.txt

# Private key
openssl genrsa -out rsa2048_private.pem 2048

# OpenSSH
chmod 600 rsa2048_private.pem
ssh-keygen -f rsa2048_private.pem -y > rsa2048_public_openssh.txt

ssh-keygen -t rsa -b 2048 -f rsa2048_private_openssh.pem -P ""
cp -fa rsa2048_private_openssh.pem rsa2048_private_openssh_old.pem
ssh-keygen -p -f rsa2048_private_openssh_old.pem -m PEM -N ""

ssh-keygen -t rsa -b 2048 -f rsa2048_private_openssh_pwd.pem -P "password"
cp -fa rsa2048_private_openssh_pwd.pem rsa2048_private_openssh_pwd_old.pem
ssh-keygen -p -f rsa2048_private_openssh_pwd_old.pem -m PEM -N "" -P "password"
