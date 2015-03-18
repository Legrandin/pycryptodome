# -*- coding: ascii -*-
#
#  Util/asn1.py : Minimal support for ASN.1 DER binary encoding.
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================
""" ASN.1 DER encoding and decoding

This module provides minimal support for encoding and decoding `ASN.1`_ DER
objects.

.. _`ASN.1`: ftp://ftp.rsasecurity.com/pub/pkcs/ascii/layman.asc

"""

from Crypto.Util.py3compat import *

from Crypto.Util.number import long_to_bytes, bytes_to_long

__all__ = [ 'DerObject', 'DerInteger', 'DerOctetString', 'DerNull',
            'DerSequence', 'DerObjectId', 'DerBitString', 'DerSetOf',
            'newDerInteger', 'newDerOctetString', 'newDerSequence',
            'newDerObjectId', 'newDerBitString', 'newDerSetOf' ]

def _isInt(x, onlyNonNegative=False):
    test = 0
    try:
        test += x
    except TypeError:
        return False
    return not onlyNonNegative or x>=0

class BytesIO_EOF(BytesIO):
    """This class differs from BytesIO in that an EOFError exception is
    raised whenever EOF is reached."""

    def __init__(self, *params):
        BytesIO.__init__(self, *params)
        self.setRecord(False)

    def setRecord(self, record):
        self._record = record
        self._recording = b("")

    def read(self, length):
        s = BytesIO.read(self, length)
        if len(s)<length:
            raise EOFError
        if self._record:
            self._recording += s
        return s

    def read_byte(self):
        return self.read(1)[0]

class _NoDerElementError(EOFError):
    pass

class DerObject(object):
        """Base class for defining a single DER object.

        This class should never be directly instantiated.
        """

        def __init__(self, asn1Id=None, payload=b(''), implicit=None,
                     constructed=False, explicit=None):
                """Initialize the DER object according to a specific ASN.1 type.

                :Parameters:
                  asn1Id : integer
                    The universal DER tag number for this object
                    (e.g. 0x10 for a SEQUENCE).
                    If None, the tag is not known yet.

                  payload : byte string
                    The initial payload of the object (that it,
                    the content octets).
                    If not specified, the payload is empty.

                  implicit : integer
                    The IMPLICIT tag number to use for the encoded object.
                    It overrides the universal tag *asn1Id*.

                  constructed : bool
                    True when the ASN.1 type is *constructed*.
                    False when it is *primitive*.

                  explicit : integer
                    The EXPLICIT tag number to use for the encoded object.
                """

                if asn1Id==None:
                    # The tag octet will be read in with ``decode``
                    self._tag_octet = None
                    return
                asn1Id = self._convertTag(asn1Id)

                # In a BER/DER identifier octet:
                # * bits 4-0 contain the tag value
                # * bit 5 is set if the type is 'constructed'
                #   and unset if 'primitive'
                # * bits 7-6 depend on the encoding class
                #
                # Class        | Bit 7, Bit 6
                # ----------------------------------
                # universal    |   0      0
                # application  |   0      1
                # context-spec |   1      0 (default for IMPLICIT/EXPLICIT)
                # private      |   1      1
                #
                if explicit is None:
                    if implicit is None:
                        self._tag_octet = asn1Id
                    else:
                        self._tag_octet = 0x80 | self._convertTag(implicit)
                    self._tag_octet |= 0x20 * constructed
                else:
                    if implicit is None:
                        self._tag_octet = 0xA0 | self._convertTag(explicit)
                    else:
                        raise ValueError("Explicit and implicit tags are mutually exclusive")
                    self._inner_tag_octet = asn1Id + 0x20 * constructed

                self.payload = payload

        def _convertTag(self, tag):
                """Check if *tag* is a real DER tag.
                Convert it from a character to number if necessary.
                """
                if not _isInt(tag):
                    if len(tag)==1:
                        tag = bord(tag[0])
                # Ensure that tag is a low tag
                if not (_isInt(tag) and 0 <= tag < 0x1F):
                    raise ValueError("Wrong DER tag")
                return tag

        @staticmethod
        def _definite_form(length):
                """Build length octets according to BER/DER
                definite form.
                """
                if length>127:
                        encoding = long_to_bytes(length)
                        return bchr(len(encoding) + 128) + encoding
                return bchr(length)

        def encode(self):
                """Return this DER element, fully encoded as a binary byte string."""

                # Concatenate identifier octets, length octets,
                # and contents octets

                output_payload = self.payload

                # In case of an EXTERNAL tag, first encode the inner
                # element.
                if hasattr(self, "_inner_tag_octet"):
                    output_payload = bchr(self._inner_tag_octet) +\
                                     self._definite_form(len(self.payload)) +\
                                     self.payload

                return bchr(self._tag_octet) +\
                       self._definite_form(len(output_payload)) +\
                       output_payload

        def _decodeLen(self, s):
                """Decode DER length octets from a file."""

                length = bord(s.read_byte())
                if length<=127:
                        return length
                payloadLength = bytes_to_long(s.read(length & 0x7F))
                # According to DER (but not BER) the long form is used
                # only when the length doesn't fit into 7 bits.
                if payloadLength<=127:
                        raise ValueError("Not a DER length tag (but still valid BER).")
                return payloadLength

        def decode(self, derEle):
                """Decode a complete DER element, and re-initializes this
                object with it.

                :Parameters:
                  derEle : byte string
                    A complete DER element.

                :Raise ValueError:
                  In case of parsing errors.
                :Raise EOFError:
                  If the DER element is too short.
                """

                s = BytesIO_EOF(derEle)
                self._decodeFromStream(s)
                # There shouldn't be other bytes left
                try:
                    b = s.read_byte()
                    raise ValueError("Unexpected extra data after the DER structure")
                except EOFError:
                    pass

                # In case of an EXTERNAL tag, further decode the inner
                # element.
                if hasattr(self, "_inner_tag_octet"):
                    self._tag_octet = self._inner_tag_octet
                    del self._inner_tag_octet
                    self.decode(self.payload)
                return self

        def _decodeFromStream(self, s):
                """Decode a complete DER element from a file."""

                try:
                    idOctet = bord(s.read_byte())
                except EOFError:
                    raise _NoDerElementError
                if self._tag_octet != None:
                    if idOctet != self._tag_octet:
                        raise ValueError("Unexpected DER tag")
                else:
                    self._tag_octet = idOctet
                length = self._decodeLen(s)
                self.payload = s.read(length)

class DerInteger(DerObject):
        """Class to model a DER INTEGER.

        An example of encoding is:

          >>> from Crypto.Util.asn1 import DerInteger
          >>> from binascii import hexlify, unhexlify
          >>> int_der = DerInteger(9)
          >>> print hexlify(int_der.encode())

        which will show ``020109``, the DER encoding of 9.

        And for decoding:

          >>> s = unhexlify(b'020109')
          >>> try:
          >>>   int_der = DerInteger()
          >>>   int_der.decode(s)
          >>>   print int_der.value
          >>> except (ValueError, EOFError):
          >>>   print "Not a valid DER INTEGER"

        the output will be ``9``.
        """

        def __init__(self, value=0, implicit=None, explicit=None):
                """Initialize the DER object as an INTEGER.

                :Parameters:
                  value : integer
                    The value of the integer.

                  implicit : integer
                    The IMPLICIT tag to use for the encoded object.
                    It overrides the universal tag for INTEGER (2).
                """

                DerObject.__init__(self, 0x02, b(''), implicit,
                                   False, explicit)
                self.value = value #: The integer value

        def encode(self):
                """Return the DER INTEGER, fully encoded as a
                binary string."""

                number = self.value
                self.payload = b('')
                while True:
                    self.payload = bchr(int(number&255)) + self.payload
                    if 128 <= number <= 255:
                        self.payload = bchr(0x00) + self.payload
                    if -128 <= number <= 255:
                        break
                    number >>= 8
                return DerObject.encode(self)

        def decode(self, derEle):
                """Decode a complete DER INTEGER DER, and re-initializes this
                object with it.

                :Parameters:
                  derEle : byte string
                    A complete INTEGER DER element.

                :Raise ValueError:
                  In case of parsing errors.
                :Raise EOFError:
                  If the DER element is too short.
                """

                return DerObject.decode(self, derEle)

        def _decodeFromStream(self, s):
                """Decode a complete DER INTEGER from a file."""

                # Fill up self.payload
                DerObject._decodeFromStream(self, s)

                # Derive self.value from self.payload
                self.value = 0
                bits = 1
                for i in self.payload:
                    self.value *= 256
                    self.value += bord(i)
                    bits <<= 8
                if self.payload and bord(self.payload[0]) & 0x80:
                    self.value -= bits

def newDerInteger(number):
    """Create a DerInteger object, already initialized with an integer."""

    der = DerInteger(number)
    return der

class DerSequence(DerObject):
        """Class to model a DER SEQUENCE.

        This object behaves like a dynamic Python sequence.

        Sub-elements that are INTEGERs behave like Python integers.

        Any other sub-element is a binary string encoded as a complete DER
        sub-element (TLV).

        An example of encoding is:

          >>> from Crypto.Util.asn1 import DerSequence, DerInteger
          >>> from binascii import hexlify, unhexlify
          >>> obj_der = unhexlify('070102')
          >>> seq_der = DerSequence([4])
          >>> seq_der.append(9)
          >>> seq_der.append(obj_der.encode())
          >>> print hexlify(seq_der.encode())

        which will show ``3009020104020109070102``, the DER encoding of the
        sequence containing ``4``, ``9``, and the object with payload ``02``.

        For decoding:

          >>> s = unhexlify(b'3009020104020109070102')
          >>> try:
          >>>   seq_der = DerSequence()
          >>>   seq_der.decode(s)
          >>>   print len(seq_der)
          >>>   print seq_der[0]
          >>>   print seq_der[:]
          >>> except (ValueError, EOFError):
          >>>   print "Not a valid DER SEQUENCE"

        the output will be::

          3
          4
          [4, 9, b'\x07\x01\x02']

        """

        def __init__(self, startSeq=None, implicit=None):
                """Initialize the DER object as a SEQUENCE.

                :Parameters:
                  startSeq : Python sequence
                    A sequence whose element are either integers or
                    other DER objects.

                  implicit : integer
                    The IMPLICIT tag to use for the encoded object.
                    It overrides the universal tag for SEQUENCE (16).
                """

                DerObject.__init__(self, 0x10, b(''), implicit, True)
                if startSeq==None:
                    self._seq = []
                else:
                    self._seq = startSeq

        ## A few methods to make it behave like a python sequence

        def __delitem__(self, n):
                del self._seq[n]
        def __getitem__(self, n):
                return self._seq[n]
        def __setitem__(self, key, value):
                self._seq[key] = value
        def __setslice__(self,i,j,sequence):
                self._seq[i:j] = sequence
        def __delslice__(self,i,j):
                del self._seq[i:j]
        def __getslice__(self, i, j):
                return self._seq[max(0, i):max(0, j)]
        def __len__(self):
                return len(self._seq)
        def __iadd__(self, item):
                self._seq.append(item)
                return self
        def append(self, item):
                self._seq.append(item)
                return self

        def hasInts(self, onlyNonNegative=True):
                """Return the number of items in this sequence that are
                integers.

                :Parameters:
                  onlyNonNegative : boolean
                    If True, negative integers are not counted in.
                """
                def _isInt2(x):
                    return _isInt(x, onlyNonNegative)
                return len(filter(_isInt2, self._seq))

        def hasOnlyInts(self, onlyNonNegative=True):
                """Return True if all items in this sequence are integers
                or non-negative integers.

                This function returns False is the sequence is empty,
                or at least one member is not an integer.

                :Parameters:
                  onlyNonNegative : boolean
                    If True, the presence of negative integers
                    causes the method to return False."""
                return self._seq and self.hasInts(onlyNonNegative)==len(self._seq)

        def encode(self):
                """Return this DER SEQUENCE, fully encoded as a
                binary string.

                :Raises ValueError:
                  If some elements in the sequence are neither integers
                  nor byte strings.
                """
                self.payload = b('')
                for item in self._seq:
                    try:
                        self.payload += item
                    except TypeError:
                        try:
                            self.payload += DerInteger(item).encode()
                        except TypeError:
                            raise ValueError("Trying to DER encode an unknown object")
                return DerObject.encode(self)

        def decode(self, derEle):
                """Decode a complete DER SEQUENCE, and re-initializes this
                object with it.

                :Parameters:
                  derEle : byte string
                    A complete SEQUENCE DER element.

                :Raise ValueError:
                  In case of parsing errors.
                :Raise EOFError:
                  If the DER element is too short.

                DER INTEGERs are decoded into Python integers. Any other DER
                element is not decoded. Its validity is not checked.
                """

                return DerObject.decode(self, derEle)

        def _decodeFromStream(self, s):
                """Decode a complete DER SEQUENCE from a file."""

                self._seq = []

                # Fill up self.payload
                DerObject._decodeFromStream(self, s)

                # Add one item at a time to self.seq, by scanning self.payload
                p = BytesIO_EOF(self.payload)
                while True:
                    try:
                        p.setRecord(True)
                        der = DerObject()
                        der._decodeFromStream(p)

                        # Parse INTEGERs differently
                        if der._tag_octet != 0x02:
                            self._seq.append(p._recording)
                        else:
                            derInt = DerInteger()
                            derInt.decode(p._recording)
                            self._seq.append(derInt.value)

                    except _NoDerElementError:
                        break
                # end

def newDerSequence(*der_objs):
    """Create a DerSequence object, already initialized with all objects
    passed as parameters."""

    der = DerSequence()
    for obj in der_objs:
        if isinstance(obj, DerObject):
            der += obj.encode()
        else:
            der += obj
    return der

class DerOctetString(DerObject):
    """Class to model a DER OCTET STRING.

    An example of encoding is:

    >>> from Crypto.Util.asn1 import DerOctetString
    >>> from binascii import hexlify, unhexlify
    >>> os_der = DerOctetString(b'\\xaa')
    >>> os_der.payload += b'\\xbb'
    >>> print hexlify(os_der.encode())

    which will show ``0402aabb``, the DER encoding for the byte string
    ``b'\\xAA\\xBB'``.

    For decoding:

    >>> s = unhexlify(b'0402aabb')
    >>> try:
    >>>   os_der = DerOctetString()
    >>>   os_der.decode(s)
    >>>   print hexlify(os_der.payload)
    >>> except (ValueError, EOFError):
    >>>   print "Not a valid DER OCTET STRING"

    the output will be ``aabb``.
    """

    def __init__(self, value=b(''), implicit=None):
        """Initialize the DER object as an OCTET STRING.

        :Parameters:
          value : byte string
            The initial payload of the object.
            If not specified, the payload is empty.

          implicit : integer
            The IMPLICIT tag to use for the encoded object.
            It overrides the universal tag for OCTET STRING (4).
        """
        DerObject.__init__(self, 0x04, value, implicit, False)

def newDerOctetString(binstring):
    """Create a DerOctetString object, already initialized with the binary
    string."""

    if isinstance(binstring, DerObject):
        der = DerOctetString(binstring.encode())
    else:
        der = DerOctetString(binstring)
    return der

class DerNull(DerObject):
    """Class to model a DER NULL element."""

    def __init__(self):
        """Initialize the DER object as a NULL."""

        DerObject.__init__(self, 0x05, b(''), None, False)

class DerObjectId(DerObject):
    """Class to model a DER OBJECT ID.

    An example of encoding is:

    >>> from Crypto.Util.asn1 import DerObjectId
    >>> from binascii import hexlify, unhexlify
    >>> oid_der = DerObjectId("1.2")
    >>> oid_der.value += ".840.113549.1.1.1"
    >>> print hexlify(oid_der.encode())

    which will show ``06092a864886f70d010101``, the DER encoding for the
    RSA Object Identifier ``1.2.840.113549.1.1.1``.

    For decoding:

    >>> s = unhexlify(b'06092a864886f70d010101')
    >>> try:
    >>>   oid_der = DerObjectId()
    >>>   oid_der.decode(s)
    >>>   print oid_der.value
    >>> except (ValueError, EOFError):
    >>>   print "Not a valid DER OBJECT ID"

    the output will be ``1.2.840.113549.1.1.1``.
    """

    def __init__(self, value='', implicit=None):
        """Initialize the DER object as an OBJECT ID.

        :Parameters:
          value : string
            The initial Object Identifier (e.g. "1.2.0.0.6.2").
          implicit : integer
            The IMPLICIT tag to use for the encoded object.
            It overrides the universal tag for OBJECT ID (6).
        """
        DerObject.__init__(self, 0x06, b(''), implicit, False)
        self.value = value #: The Object ID, a dot separated list of integers

    def encode(self):
        """Return the DER OBJECT ID, fully encoded as a
        binary string."""

        comps = map(int,self.value.split("."))
        if len(comps)<2:
            raise ValueError("Not a valid Object Identifier string")
        self.payload = bchr(40*comps[0]+comps[1])
        for v in comps[2:]:
            enc = []
            while v:
                enc.insert(0, (v & 0x7F) | 0x80)
                v >>= 7
            enc[-1] &= 0x7F
            self.payload += b('').join(map(bchr, enc))
        return DerObject.encode(self)

    def decode(self, derEle):
        """Decode a complete DER OBJECT ID, and re-initializes this
        object with it.

        :Parameters:
            derEle : byte string
                A complete DER OBJECT ID.

        :Raise ValueError:
            In case of parsing errors.
        :Raise EOFError:
            If the DER element is too short.
        """

        return DerObject.decode(self, derEle)

    def _decodeFromStream(self, s):
        """Decode a complete DER OBJECT ID from a file."""

        # Fill up self.payload
        DerObject._decodeFromStream(self, s)

        # Derive self.value from self.payload
        p = BytesIO_EOF(self.payload)
        comps = list(map(str, divmod(bord(p.read_byte()),40)))
        v = 0
        try:
            while True:
                c = p.read_byte()
                v = v*128 + (bord(c) & 0x7F)
                if not (bord(c) & 0x80):
                    comps.append(str(v))
                    v = 0
        except EOFError:
            pass
        self.value = '.'.join(comps)

def newDerObjectId(dottedstring):
    """Create a DerObjectId object, already initialized with the given Object
    Identifier (a dotted string)."""

    der = DerObjectId(dottedstring)
    return der

class DerBitString(DerObject):
    """Class to model a DER BIT STRING.

    An example of encoding is:

    >>> from Crypto.Util.asn1 import DerBitString
    >>> from binascii import hexlify, unhexlify
    >>> bs_der = DerBitString(b'\\xaa')
    >>> bs_der.value += b'\\xbb'
    >>> print hexlify(bs_der.encode())

    which will show ``040300aabb``, the DER encoding for the bit string
    ``b'\\xAA\\xBB'``.

    For decoding:

    >>> s = unhexlify(b'040300aabb')
    >>> try:
    >>>   bs_der = DerBitString()
    >>>   bs_der.decode(s)
    >>>   print hexlify(bs_der.value)
    >>> except (ValueError, EOFError):
    >>>   print "Not a valid DER OCTET STRING"

    the output will be ``aabb``.
    """

    def __init__(self, value=b(''), implicit=None):
        """Initialize the DER object as a BIT STRING.

        :Parameters:
          value : byte string
            The initial, packed bit string.
            If not specified, the bit string is empty.
          implicit : integer
            The IMPLICIT tag to use for the encoded object.
            It overrides the universal tag for OCTET STRING (3).
        """
        DerObject.__init__(self, 0x03, b(''), implicit, False)
        self.value = value #: The bitstring value (packed)

    def encode(self):
        """Return the DER BIT STRING, fully encoded as a
        binary string."""

        # Add padding count byte
        self.payload = b('\x00') + self.value
        return DerObject.encode(self)

    def decode(self, derEle):
        """Decode a complete DER BIT STRING, and re-initializes this
        object with it.

        :Parameters:
            derEle : byte string
                A complete DER BIT STRING.

        :Raise ValueError:
            In case of parsing errors.
        :Raise EOFError:
            If the DER element is too short.
        """

        return DerObject.decode(self, derEle)

    def _decodeFromStream(self, s):
        """Decode a complete DER BIT STRING DER from a file."""

        # Fill-up self.payload
        DerObject._decodeFromStream(self, s)

        if self.payload and bord(self.payload[0])!=0:
            raise ValueError("Not a valid BIT STRING")

        # Fill-up self.value
        self.value = b('')
        # Remove padding count byte
        if self.payload:
            self.value = self.payload[1:]

def newDerBitString(binstring):
    """Create a DerStringString object, already initialized with the binary
    string."""

    if isinstance(binstring, DerObject):
        der = DerBitString(binstring.encode())
    else:
        der = DerBitString(binstring)
    return der

class DerSetOf(DerObject):
    """Class to model a DER SET OF.

    An example of encoding is:

    >>> from Crypto.Util.asn1 import DerBitString
    >>> from binascii import hexlify, unhexlify
    >>> so_der = DerSetOf([4,5])
    >>> so_der.add(6)
    >>> print hexlify(so_der.encode())

    which will show ``3109020104020105020106``, the DER encoding
    of a SET OF with items 4,5, and 6.

    For decoding:

    >>> s = unhexlify(b'3109020104020105020106')
    >>> try:
    >>>   so_der = DerSetOf()
    >>>   so_der.decode(s)
    >>>   print [x for x in so_der]
    >>> except (ValueError, EOFError):
    >>>   print "Not a valid DER SET OF"

    the output will be ``[4, 5, 6]``.
    """

    def __init__(self, startSet=None, implicit=None):
        """Initialize the DER object as a SET OF.

        :Parameters:
          startSet : container
            The initial set of integers or DER encoded objects.
          implicit : integer
            The IMPLICIT tag to use for the encoded object.
            It overrides the universal tag for SET OF (17).
        """
        DerObject.__init__(self, 0x11, b(''), implicit, True)
        self._seq = []
        self._elemOctet = None
        if startSet:
            for e in startSet:
                self.add(e)

    def __getitem__(self, n):
        return self._seq[n]

    def __iter__(self):
        return iter(self._seq)

    def __len__(self):
        return len(self._seq)

    def add(self, elem):
        """Add an element to the set.

        :Parameters:
            elem : byte string or integer
              An element of the same type of objects already in the set.
              It can be an integer or a DER encoded object.
        """
        if _isInt(elem):
            eo = 0x02
        else:
            eo = bord(elem[0])
        if self._elemOctet != eo:
            if self._elemOctet:
                raise ValueError("New element does not belong to the set")
            self._elemOctet = eo
        if not elem in self._seq:
            self._seq.append(elem)

    def decode(self, derEle):
        """Decode a complete SET OF DER element, and re-initializes this
        object with it.

        DER INTEGERs are decoded into Python integers. Any other DER
        element is left undecoded; its validity is not checked.

        :Parameters:
            derEle : byte string
                A complete DER BIT SET OF.

        :Raise ValueError:
            In case of parsing errors.
        :Raise EOFError:
            If the DER element is too short.
        """

        return DerObject.decode(self, derEle)

    def _decodeFromStream(self, s):
        """Decode a complete DER SET OF from a file."""

        self._seq = []

        # Fill up self.payload
        DerObject._decodeFromStream(self, s)

        # Add one item at a time to self.seq, by scanning self.payload
        p = BytesIO_EOF(self.payload)
        setIdOctet = -1
        while True:
            try:
                p.setRecord(True)
                der = DerObject()
                der._decodeFromStream(p)

                # Verify that all members are of the same type
                if setIdOctet < 0:
                    setIdOctet = der._tag_octet
                else:
                    if setIdOctet != der._tag_octet:
                        raise ValueError("Not all elements are of the same DER type")

                # Parse INTEGERs differently
                if setIdOctet != 0x02:
                    self._seq.append(p._recording)
                else:
                    derInt = DerInteger()
                    derInt.decode(p._recording)
                    self._seq.append(derInt.value)

            except _NoDerElementError:
                break
        # end

    def encode(self):
        """Return this SET OF DER element, fully encoded as a
        binary string.
        """

        # Elements in the set must be ordered in lexicographic order
        ordered = []
        for item in self._seq:
            if _isInt(item):
                bys = DerInteger(item).encode()
            else:
                bys = item
            ordered.append(bys)
        ordered.sort()
        self.payload = b('').join(ordered)
        return DerObject.encode(self)

def newDerSetOf(*der_objs):
    """Create a DerSequence object, already initialized with all objects
    passed as parameters."""

    der = DerSetOf()
    for obj in der_objs:
        if isinstance(obj, DerObject):
            der.add(obj.encode())
        else:
            der.add(obj)
    return der
