#
# PGP CONSTANTS
#

#
# Cipher Type Byte Types
#
CTBT_PKEP     = 0x1
CTBT_SIG      = 0x2
CTBT_SKCERT   = 0x5
CTBT_PKCERT   = 0x6
CTBT_COMPR    = 0x8
CTBT_CKEP     = 0x9
CTBT_PLAIN    = 0xB
CTBT_TRUST    = 0xC
CTBT_USERID   = 0xD
CTBT_COMMENT  = 0xE


#
# Length Types
#
LEN_1         = 0x0
LEN_2         = 0x1
LEN_4         = 0x2
LEN_UNKNOWN   = 0x3
PACKET_LENGTH={LEN_1:1, LEN_2: 2, LEN_4: 4, LEN_UNKNOWN: 0}

#
# Signature Types
#
SIG_BIN       = 0x0
SIG_TXT       = 0x1
SIG_KEY       = 0x10
SIG_KEY1      = 0x11
SIG_KEY2      = 0x12
SIG_KEY3      = 0x13
SIG_COMP      = 0x20
SIG_REVOKE    = 0x30
SIG_TIME      = 0x40

# Ciphering algorithms
CIPHER_NONE = 0
CIPHER_IDEA = 1

# List of the supported ciphering algorithms
CIPHER_LIST = [CIPHER_NONE, CIPHER_IDEA]

# PK algorithms
PK_NONE = 0
PK_RSA = 1

# List of the supported PK algorithms
PK_LIST = [PK_RSA]

# Hashing algorithms
HASH_MD5=1

# List of the supported hashing algorithms
HASH_LIST = [HASH_MD5]

# Compression algorithms
COMPRESS_NONE = 0
COMPRESS_ZLIB = 1

# List of the supported compression algorithms
COMPRESS_LIST = [COMPRESS_ZLIB]

# ASN.1 identifier string that precedes v2.3 message digests
ASN_STRING='0 0\014\006\010*\206H\206\367\015\002\005\005\000\004\020'

# Packet sizes: despite the flexibility of PGP's packet structure,
# much code assumes things about the size of the field giving 
# the packet's length.  For example, secret and public key
# certificates are assumed to have a 16-bit length field.
# The following dictionary maps packet types to the expected size.
# If the type isn't here, then PGP doesn't have any expectation
# of its size.

PACKET_SIZES={CTBT_SKCERT:16, CTBT_PKCERT:16, CTBT_SIG:16}

