#!/usr/bin/env python3

import time
from Crypto.PublicKey import RSA
from Crypto.Math import Numbers
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import long_to_bytes
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  create_string_buffer,
                                  c_size_t)

ITER = 100

print(Numbers._implementation)

rsa_pem="""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1maRsgBxvk1m1LcQMrN/oAfPq/V5/LkeUL/CdTs/DOe+dOIW
rvfibUrhgLwg170+qIpsv2+HOA5hPIl5tbBDsgCo/4hWo7EodeNumKdWnzhS0Cjp
Z1UQALAsGen6UugxFbiTCaq7Hhzx4stjadY31Gd1zkUj6jH2StJ5TLw2XdijXgB+
07V2lYd/vxAtvrizISSROY5JQxTpNyaSbhOD+Ku1iJvqlU64wMocYsjp2D9BiICV
xeZF7W0yUV/gxYwTaMrYRpThjaQ2aMb0PmHXybymM93Np671t5vDltSp9I4qmr4I
NsxFXkNTBTVyKOk9JartRrlS3vrg9XM5vyb1qQIDAQABAoIBACzgr2KJAUYKQZoI
75UNSYuf1vJxoaUqwpO4b+XGDv6Oi6k/oevh6z1hTS57Moy2CiWRRA4WNEGhkOzx
Ac7sJF9gD//c8/WzoXp7rqy5akJNsdfsmF6OyZi7R5/s//7Wp1+akPyXBi/ZczA7
zoVa17jYJyqUAl6FMr6aq9VKGD8wNTjSp+YhtBMdWegjpGJfOb19UY13hPfDqPGQ
Ydp0l0/0L6HAY97C25fUYeKRp9bnIXCKUineFmwSRjYzcoVOJ/PwiuJ0vBa/0gWw
KKTYE4ZJRDPVFt+7NfSVrLpeTh0YQ8s8MSm2ZCqF/HJEzlhF+sBxx/Yi5O4SrEP6
vuqgzQECgYEA/E9vn6XKnJXX3hiy0XVsUQK+Ana2xn63TxmiMJtrrUjD5WCiy9kD
eTU82igdg9JJGBWOd7mkSAWxVZT9MPaQ4/Vz6ggoZcPHZokmVP7qPePNmFXX6Jdz
hQx8HD0QcwwaYbIJ91WdoAP/cEuu+o+WPKB0CDYWrv3Dx9eTircemlECgYEA2Yk2
WXkOdD2KlnZgHNYp23F2XP6dF4Ny5n478thlJXdexRwRDSKCN/41jfC0FlPpZBcF
7EFTo+p7lhyJVxPBWSOIhJArMe98bdWoo+6TBuAPLisu7+i+HVRaoyHf0x3t7ViG
JqQOGjHN0G57cgSCrpaFwE2bAZ4dkA27M8Oy99kCgYEAw+HoB0nvwyGSNht2uKcx
MLOwULlZrUEzj3WXNaV0M1QKwkoEGb6hs7hhRf1e7LiVht01fj3iDQheZNMGvryu
QEyPcWJj+p3EcRaJa/N8aBAzzdDXjvwF84V91W6TFr6OvMo8colFlrWD2urnLh/L
w8XOT5Guiqz5Em2LXmZMnAECgYEAuZ1Ksq2Il8arKhd3iyNyM7xssozOnfGbaPDt
VhkutPlV8/ou0nZPhldyetqXzzVqP+0lMKHNLGA3c66Fwbcpk1Wudu5M7R7bnRxh
+P7olUU5rrtKIYsGLSB89hVBVnKDQbH3RaFWJyO36dFbo74Vg8ML/To6uPahYvlU
cqbZXoECgYAOybAyRS9vivcYoKywxtI0aU1HHibPrUl3izYLfDxfWgA0S6IGcBg1
Sx6XG8GYbzkouGb30yjIpn7JB1147DH1oxf8wcHXbAsgNX4IC6rQ1Iwef9P4pORF
icKO95pcPRhmfzuqfhEu/d/ZYjabao95baBHcrRxEbXZtjg88KVXKg==
-----END RSA PRIVATE KEY-----
"""

c_defs = """
int monty_pow(const uint8_t *base,
               const uint8_t *exp,
               const uint8_t *modulus,
               uint8_t       *out,
               size_t len,
               uint64_t seed);
"""

_raw_montgomery = load_pycryptodome_raw_lib("Crypto.Math._montgomery", c_defs)

key = RSA.import_key(rsa_pem)
message = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
SIZE = key.size_in_bytes()

# -----------------------------------------------------------------
start = time.time()
for x in range(ITER):
	result_cpython = pow(message, key.d, key.n)
end = time.time()
print("CPython =", end-start)

# -----------------------------------------------------------------
base_b = long_to_bytes(message, SIZE)
exp_b = long_to_bytes(key.d, SIZE)
modulus_b = long_to_bytes(key.n, SIZE)
out = create_string_buffer(SIZE)

start = time.time()
for _ in range(ITER):
    _raw_montgomery.monty_pow(
                base_b,
                exp_b,
                modulus_b,
                out,
                c_size_t(SIZE),
                32
                )
end = time.time()
my_time = end-start
print("Custom modexp =", my_time)

# -----------------------------------------------------------------
mg = Integer(message)
md = Integer(key.d)
mn = Integer(key.n)
start = time.time()
for x in range(ITER):
	result_gmp = pow(mg, md, mn)
end = time.time()
gmp_time = end - start
print("GMP =", gmp_time)

# -----------------------------------------------------------------
print("%.2f%%" % float((my_time/gmp_time-1)*100), "slower")
