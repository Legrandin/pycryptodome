Frequently Asked Questions
--------------------------

Is CTR cipher mode compatible with BouncyCastle's?
++++++++++++++++++++++++++++++++++++++++++++++++++

Yes. When you instantiate your AES cipher in Java::

   Cipher  cipher = Cipher.getInstance("AES/CTR/NoPadding");

   SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
   IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);

   cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

You are effectively using :ref:`ctr_mode` without a fixed nonce and with
a 128-bit big endian counter starting at 0.
The counter will wrap around only after 2¹²⁸ blocks.

You can replicate the same keystream in PyCryptodome with::

   ivSpec = b'\x00' * 16
   ctr = AES.new(keySpec, AES.MODE_CTR, initial_value=ivSpec)
