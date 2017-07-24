``Crypto.Cipher`` package
=========================

This package contains algorithms for protecting the confidentiality
of data.

There are three main types of encryption algorithms:

* **Symmetric**: all parties that want to decrypt or encrypt
  the data share the same secret key.
  Symmetric algorithms are typically very fast and can process
  very large amount of data.

* **Asymmetric**: senders and receivers have different keys.
  Senders use *public* keys (non-secret) whereas receivers
  use *private* keys (secret).
  Asymmetric algorithms are typically very slow and can process
  only very small payloads.
* **Hybrid**: as one can imagine, the two types of algorithms
  above can be combined by using *asymmetric* algorithms for
  delivering a short-lived and message-specific secret,
  and *symmetric* algorithms for encrypting the bulk of the data.

Symmetric algorithms
--------------------

Symmetric algorithms are further sub-divided into two types:

* **Stream ciphers**: the most natural kind of ciphers that
  take a certain amount of data and returns the exact same
  amount just in encrypted form (example: :doc:`chacha20`).
* **Block ciphers**: a cipher that only works on a fixed amount
  of data (example: AES, 16 bytes block size).
  
  Block ciphers are only useful in combination with *cipher modes*.
  For instance, AES in CTR mode is equivalent to a stream cipher
  and can process messages of any length;
  AES in GCM mode can do that **and** also generate a
  *Message Authentication Code* (MAC).

Historic ciphers
----------------

xxx
