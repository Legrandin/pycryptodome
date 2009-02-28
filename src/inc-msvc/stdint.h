/*
 *  inc-msvc/stdint.h: Partial stdint.h for MSVC compiler
 *
 * Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 */
#ifndef PYCRYPTO_MSVC_STDINT_H
#define PYCRYPTO_MSVC_STDINT_H

typedef signed __int8  int8_t;
typedef signed __int16 int16_t;
typedef signed __int32 int32_t;
typedef signed __int64 int64_t;

typedef unsigned __int8  uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

/* Define the "inline" keyword */
#ifndef inline
# define inline __inline
#endif /* inline */


#endif /* PYCRYPTO_MSVC_STDINT_H */
/* vim:set ts=4 sw=4 sts=4 expandtab: */
