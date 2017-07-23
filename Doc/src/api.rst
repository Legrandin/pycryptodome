API documentation
-----------------

All cryptographic functionalities are organized in sub-packages;
each sub-package is dedicated to solving a specific class of problems.

* The :doc:`cipher` contains modules for protecting **confidentility**
  that is, for encrypting and decrypting data (example: AES).
* The :doc:`signature` contains modules for assuring **authenticity**,
  that is, for creating and verifying digital signatures of messages
  (example: PKCS#1 v1.5).
* The :doc:`hash` contains modules for creating cryptographic **digests**
  (example: SHA-256).
* The :doc:`public_key` contains modules for generating, exporting or importing
  *public keys* (example: RSA or ECC).
* The :doc:`protocol` contains modules for faciliting secure communications
  between parties, in most cases by leveraging cryptograpic primitives
  from other modules (example: Shamir's Secret Sharing scheme).
* The :doc:`io` contains modules for dealing with encodings commonly used
  for cryptographic data (example: PEM).
* The :doc:`util` contains general purpose routines (example: XOR for byte
  strings).

In certain cases, there is some overlap between these categories.
For instance, **authenticity** is also provided by *Message Authentication Codes*,
and some can be built using digests, so they are included in the ``Crypto.Hash``
package (example: HMAC).
Also, cryptographers have over time realized that encryption without
**authentication** is often of limited value so recent ciphers found in the
``Crypto.Cipher`` package embed it (example: GCM).

*PyCryptodome* strives to maintain strong backward compatibility with the old
*PyCrypto*'s API (except for those few cases where that is harmful to security)
so a few modules don't appear where they should (example: the ASN.1 module
is under ``Crypto.Util`` as opposed to ``Crypto.IO``).
