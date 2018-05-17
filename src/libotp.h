/**
 * MIT License
 * Copyright (c) 2017 Brady Love
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#ifndef OTP_H
#define OTP_H

#include <string>

namespace OTP {
	namespace Bytes {
		typedef uint8_t Byte;
		typedef std::basic_string<Byte> ByteString;

		void clearByteString(ByteString *bstr);
		void swizzleByteString(ByteString *target, ByteString *source);
		std::string toHexString(const ByteString &bstr);
		ByteString u32beToByteString(uint32_t num);
		ByteString u64beToByteString(uint64_t num);
		ByteString fromBase32(const std::string &b32str);
		ByteString fromUnpaddedBase32(const std::string &b32str);
		std::string toBase32(const ByteString &b32str);

		class ByteStringDestructor {
			private:
				/** The byte string to clear. */
				ByteString * m_bs;

			public:
				ByteStringDestructor(ByteString * bs) : m_bs(bs) {}
				~ByteStringDestructor() { clearByteString(m_bs); }
		};
	}
	typedef Bytes::ByteString (*HmacFunc)(const Bytes::ByteString &, const Bytes::ByteString &);

	Bytes::ByteString sha1(const Bytes::ByteString &msg);
	Bytes::ByteString hmacSha1(const Bytes::ByteString &key, const Bytes::ByteString &msg, size_t blockSize = 64);

	Bytes::ByteString hmacSha1_64(const Bytes::ByteString &key, const Bytes::ByteString &msg);
	uint32_t hotp(const Bytes::ByteString &key, uint64_t counter, size_t digitCount = 6, HmacFunc hmac = hmacSha1_64);
	uint32_t totp(const Bytes::ByteString &key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount = 6, HmacFunc hmac = hmacSha1_64);
}

#endif

