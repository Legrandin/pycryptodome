# -*- coding: utf-8 -*-
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

"""Public-key encryption and signature algorithms.

Public-key encryption uses two different keys, one for encryption and
one for decryption.  The encryption key can be made public, and the
decryption key is kept private.  Many public-key algorithms can also
be used to sign messages, and some can *only* be used for signatures.

========================  =============================================
Module                    Description
========================  =============================================
Crypto.PublicKey.DSA      Digital Signature Algorithm (Signature only)
Crypto.PublicKey.ElGamal  (Signing and encryption)
Crypto.PublicKey.RSA      (Signing, encryption, and blinding)
========================  =============================================

:undocumented: _DSA
"""

__all__ = ['RSA', 'DSA', 'ElGamal']

def _extract_sp_info(x509_certificate):
    """Extract subjectPublicKeyInfo from a DER X.509 certificate."""

    from Crypto.Util.asn1 import DerSequence, DerInteger

    try:
        # This code will partially parse tbsCertificate
        # to get to subjectPublicKeyInfo.
        #
        # However, the first 2 elements of tbsCertificate are:
        #
        #   version [0]  Version DEFAULT v1,
        #   serialNumber         CertificateSerialNumber,
        #
        # where:
        #
        #   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
        #   CertificateSerialNumber  ::=  INTEGER
        #
        # In order to know the position of subjectPublicKeyInfo
        # in the tbsCertificate SEQUENCE, we try to see if the
        # first element is an untagged INTEGER (that is, the
        # certificate serial number).

        x509_tbs_cert = DerSequence()
        x509_tbs_cert.decode(x509_certificate[0])

        index = -1  # Sentinel
        try:
            _ = x509_tbs_cert[0] + 1
            # Still here? There was no version then
            index = 5
        except TypeError:
            # Landed here? Version was there
            x509_version = DerInteger(explicit=0)
            x509_version.decode(x509_tbs_cert[0])
            index = 6

        if index in (5, 6):
            return x509_tbs_cert[index]

    except (TypeError, IndexError, ValueError, EOFError):
        pass

    raise ValueError("Cannot extract subjectPublicKeyInfo")

