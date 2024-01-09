Examples
========

Encrypt data with AES
~~~~~~~~~~~~~~~~~~~~~

The following code generates a new AES-128 key and encrypts a piece of data into a file.
We use the :ref:`CTR mode <ctr_mode>` (which is a :ref:`classic mode of operation <classic_cipher_modes>`,
simple but not erecommended anymore).

With CTR alone, the receiver is not able to detect if the *ciphertext* (i.e., the encrypted
data) was modified while in transit. To address that risk, we also attach
a MAC authentication tag (HMAC with SHA256), made with a second key.

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
    from Crypto.Random import get_random_bytes

    data = 'secret data to transmit'.encode()

    aes_key = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(data)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()

    for open("encrypted.bin", "wb") as f:
        f.write(tag)
        f.write(nonce)
        f.write(ciphertext)

    # Share securely aes_key and hmac_key with the receiver
    # encrypted.bin can be sent over an unsecure channel

At the other end, the receiver can securely load the piece of data back (if they know the two keys!).
Note that the code generates a ``ValueError`` exception when tampering is detected.

.. code-block:: python

    import sys
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256

    # Somehow, the receiver securely get aes_key and hmac_key
    # encrypted.bin can be sent over an unsecure channel

    with open("encrypted.bin", "rb") as f:
        tag = f.read(32)
        nonce = f.read(8)
        ciphertext = f.read()

    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        tag = hmac.update(nonce + ciphertext).verify(tag)
    except ValueError:
        print("The message was modified!")
        sys.exit(1)

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    message = cipher.decrypt(ciphertext)
    print("Message:", message.decode())

Encrypt and authenticate data in one step
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The code in the previous section contains three subtle but important design decisions:
the *nonce* of the cipher is authenticated, the authentication is performed
after encryption, and encryption and authentication use two uncorrelated keys.
It is not easy to securely combine cryptographic primitives,
so more modern cryptographic cipher
modes have been created such as, the :ref:`OCB mode <ocb_mode>`
(see also other :ref:`authenticated encryption modes <modern_cipher_modes>`
like :ref:`EAX <eax_mode>`, :ref:`GCM <gcm_mode>`, :ref:`CCM <ccm_mode>`, :ref:`SIV <siv_mode>`).

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    data = 'secret data to transmit'.encode()

    aes_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    assert len(cipher.nonce) == 15

    with open("encrypted.bin", "wb") as f:
        f.write(tag)
        f.write(cipher.nonce)
        f.write(ciphertext)

    # Share securely aes_key and hmac_key with the receiver
    # encrypted.bin can be sent over an unsecure channel

Decryption is also simpler:

.. code-block:: python

    import sys
    from Crypto.Cipher import AES

    # Somehow, the receiver securely get aes_key and hmac_key
    # encrypted.bin can be sent over an unsecure channel

    with open("encrypted.bin", "rb") as f:
        tag = f.read(16)
        nonce = f.read(15)
        ciphertext = f.read()

    cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
    try:
        message = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("The message was modified!")
        sys.exit(1)

    print("Message:", message.decode())

Generate an RSA key
~~~~~~~~~~~~~~~~~~~

The following code generates a new RSA key pair (secret) and saves it into a file, protected by a password.
We use the :ref:`scrypt <scrypt_func>` key derivation function to thwart dictionary attacks.
At the end, the code prints our the RSA public key in ASCII/PEM format:

.. code-block:: python

    from Crypto.PublicKey import RSA

    secret_code = "Unguessable"
    key = RSA.generate(2048)
    encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                                  protection="scryptAndAES128-CBC",
                                  prot_params={'iteration_count':131072})
   
    with open("rsa_key.bin", "wb") as f:
        f.write(encrypted_key)
    
    print(key.publickey().export_key())

The following code reads the private RSA key back in, and then prints again the public key:

.. code-block:: python

    from Crypto.PublicKey import RSA

    secret_code = "Unguessable"
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)

    print(key.publickey().export_key())


Generate public key and private key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code generates public key stored in ``receiver.pem`` and private key stored in ``private.pem``. These files will be used in the examples below. Every time, it generates different public key and private key pair.

.. code-block:: python

    from Crypto.PublicKey import RSA

    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open("receiver.pem", "wb") as f:
        f.write(public_key)

Encrypt data with RSA
~~~~~~~~~~~~~~~~~~~~~

The following code encrypts a piece of data for a receiver we have the RSA public key of.
The RSA public key is stored in a file called ``receiver.pem``.

Since we want to be able to encrypt an arbitrary amount of data, we use a hybrid encryption scheme.
We use RSA with PKCS#1 :ref:`OAEP <rsa_oaep>` for asymmetric encryption of an AES session key.
The session key can then be used to encrypt all the actual data.

As in the first example, we use the EAX mode to allow detection of unauthorized modifications.

.. code-block:: python

    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES, PKCS1_OAEP

    data = "I met aliens in UFO. Here is the map.".encode("utf-8")

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    with open("encrypted_data.bin", "wb") as f:
        f.write(enc_session_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)

The receiver has the private RSA key. They will use it to decrypt the session key
first, and with that the rest of the file:

.. code-block:: python

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP

    private_key = RSA.import_key(open("private.pem").read())

    with open("encrypted_data.bin", "rb") as f:
        enc_session_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))
