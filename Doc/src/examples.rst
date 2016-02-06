Examples
========

Encrypt data with AES
~~~~~~~~~~~~~~~~~~~~~

The following code generates a new AES128 key and encrypts a piece of data into a file.
We use the `EAX mode`_ because it allows the receiver to detect any
unauthorized modification (similarly, we could have used other `authenticated
encryption modes`_ like `GCM`_, `CCM`_ or `SIV`_).

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]

At the other end, the receiver can securely load the piece of data back (if they know the key!).
Note that the code generates a ``ValueError`` exception when tampering is detected.

.. code-block:: python

    from Crypto.Cipher import AES

    file_in = open("encrypted.bin", "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    
    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

Generate an RSA key
~~~~~~~~~~~~~~~~~~~

The following code generates a new RSA key pair (secret) and saves it into a file, protected by a password.
We use the `scrypt`_ key derivation function to thwart dictionary attacks.
At the end, the code prints our the RSA public key in ASCII/PEM format:

.. code-block:: python

    from Crypto.PublicKey import RSA

    secret_code = "Unguessable"
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8,
                                  protection="scryptAndAES128-CBC")
    
    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)

    print key.publickey().exportKey()

The following code reads the private RSA key back in, and then prints again the public key:

.. code-block:: python

    from Crypto.PublicKey import RSA

    secret_code = "Unguessable"
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)

    print key.publickey().exportKey()


Encrypt data with RSA
~~~~~~~~~~~~~~~~~~~~~

The following code encrypts a piece of data for a receiver we have the RSA public key of.
The RSA public key is stored in a file called ``receiver.pem``.

Since we want to be able to encrypt an arbitrary amount of data, we use a hybrid encryption scheme.
We use RSA with PKCS#1 `OAEP`_ for asymmetric encryption of an AES session key.
The session key can then be used to encrypt all the actual data.

As in the first example, we use the EAX mode to allow detection of unauthorized modifications.

.. code-block:: python

    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES, PKCS1_OAEP

    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    file_out.write(cipher_rsa.encrypt(session_key))

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]

The receiver has the private RSA key. They will use it to decrypt the session key
first, and with that the rest of the file:

.. code-block:: python

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP

    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
       [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

.. _EAX mode: http://en.wikipedia.org/wiki/EAX_mode
.. _CCM: http://en.wikipedia.org/wiki/CCM_mode
.. _GCM: http://en.wikipedia.org/wiki/GCM_mode
.. _SIV: http://tools.ietf.org/html/rfc5297
.. _scrypt: http://it.wikipedia.org/wiki/Scrypt
.. _OAEP: http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
.. _authenticated encryption modes: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
