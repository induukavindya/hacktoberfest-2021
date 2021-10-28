from struct import pack, unpack

const_h = [
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
]

const_k = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

class SHA256:
	def __init__(self, message:bytes=b''):
		self.h = const_h.copy()
		self.k = const_k.copy()
		self._msg = message
		self._length = len(self._msg)
		
		while len(self._msg) >= 64:
			self._compress(self._msg[:64])
			self._msg = self._msg[64:]

	def _pad(self, data:bytes)->bytes:
		if len(data) <= 55:
			K = 55 - len(data)
		else:
			K = 119 - len(data)
		data += b'\x80' + b'\x00' * K + pack('>Q', self._length*8)
		return data

	def _to_words(self, chunk:bytes)->list:
		words = [unpack('>I', chunk[i:i+4])[0] for i in range(0, 64, 4)]
		return words

	def _rotr32(self, inp:int, n:int)->int:
		return ((inp>>n) | (inp<<(32-n)))%2**32

	def _compress(self, chunk:bytes):
		w = self._to_words(chunk)
			
		for i in range(16, 64):
			s0 = self._rotr32(w[i-15], 7) ^ self._rotr32(w[i-15], 18) ^ (w[i-15] >> 3)
			s1 = self._rotr32(w[i-2], 17) ^ self._rotr32(w[i-2], 19) ^ (w[i-2] >> 10)
			w.append((w[i-16] + s0 + w[i-7] + s1)%2**32)

		a, b, c, d, e, f, g, h = self.h

		for i in range(64):
			s1 = self._rotr32(e, 6) ^ self._rotr32(e, 11) ^ self._rotr32(e, 25)
			ch = (e & f) ^ ((~e) & g)
			temp1 = (h + s1 + ch + self.k[i] + w[i])%2**32
			s0 = self._rotr32(a, 2) ^ self._rotr32(a, 13) ^ self._rotr32(a, 22)
			maj = (a & b) ^ (a & c) ^ (b & c)
			temp2 = s0 + maj

			h = g
			g = f
			f = e
			e = (d + temp1)%2**32
			d = c
			c = b
			b = a
			a = (temp1 + temp2)%2**32

		self.h[0] = (self.h[0] + a)%2**32
		self.h[1] = (self.h[1] + b)%2**32
		self.h[2] = (self.h[2] + c)%2**32
		self.h[3] = (self.h[3] + d)%2**32
		self.h[4] = (self.h[4] + e)%2**32
		self.h[5] = (self.h[5] + f)%2**32
		self.h[6] = (self.h[6] + g)%2**32
		self.h[7] = (self.h[7] + h)%2**32

	def digest(self)->bytes:
		new = SHA256()
		new._msg = self._msg[:]
		new._length = self._length
		new.h = self.h[:]
		new._msg = new._pad(new._msg)
		while new._msg:
			new._compress(new._msg[:64])
			new._msg = new._msg[64:]

		digest = b''.join([pack('>I', x) for x in new.h])
		return digest

	def update(self, message:bytes):
		self._msg += message
		self._length += len(message)

		while len(self._msg) >= 64:
			self._compress(self._msg[:64])
			self._msg = self._msg[64:]
