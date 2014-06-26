Examples
========

Encrypt data with AES
~~~~~~~~~~~~~~~~~~~~~

The following code generates a new AES key and encrypts a piece of data into a file:

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    f = open("encrypted.bin", "wb")
    key = get_random_bytes(16)        # AES-128
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    [ f.write(x) for x in (nonce, tag, ciphertext) ]

At the other end, the receiver can securely load the piece of data back (if they know the key!):

.. code-block:: python

    from Crypto.Cipher import AES

    f = open("encrypted.bin", "rb")
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read()
    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print "Error detected"
        raise

