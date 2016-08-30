package ar.edu.iese.criptolab.cifradores;

/**
 * Clase que implementa el algoritmo de cifrado TRIVIUM TOY.
 * 
 * Versión usando ints (32 bits).
 * 
 */
public class TriviumToy32 {

	int s1, s2, s31, s32;
	int t1, t2, t3, z;

	public void process(byte[] inbuf, int inOfs, byte[] outbuf, int outOfs,
			int len) throws Exception {

		int outEnd = outOfs + len;
		for (; outOfs < outEnd; outOfs += 2, inOfs += 2) {

			t1 = (s1 >>> 32 - 22) ^ (s1 >>> 32 - 31);
			t2 = (s2 >>> 32 - 23) ^ (s2 >>> 32 - 28);
			t3 = (s31 >>> 32 - 22) ^ ((s31 << 37 - 32) | (s32 >>> 64 - 37));

			z = t1 ^ t2 ^ t3;

			t1 ^= ((s1 >>> 32 - 30) & (s1 >>> 32 - 29))
					^ (s2 >>> 32 - 26);
			t2 ^= ((s2 >>> 32 - 27) & (s2 >>> 32 - 26))
					^ (s31 >>> 32 - 29);
			t3 ^= (((s31 << 35 - 32) | (s32 >>> 64 - 35)) & ((s31 << 36 - 32) | (s32 >>> 64 - 36)))
					^ (s1 >>> 32 - 23);

			if (outOfs + 1 >= outEnd)
				break;

			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			outbuf[outOfs + 1] = (byte) (inbuf[inOfs + 1] ^ z >> 8);

			s1 = (s1 >>> 16) | (t3 << 16);
			s2 = (s2 >>> 16) | (t1 << 16);
			s32 = (s31 << 16);
			s31 = (s31 >>> 16) | (t2 << 16);
		}

		for (; outOfs < outEnd; outOfs++, inOfs++) {
			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			z >>= 8;
			s1 = (s1 >>> 8) | (t3 << 24);
			s2 = (s2 >>> 8) | (t1 << 24);
			s32 = (s32 >>> 8) | (s31 << 24);
			s31 = (s31 >>> 8) | (t2 << 24);
		}
	}

	public void setupKey(int mode, byte[] key, int ofs) throws Exception {

		// xxx - confirmar
		s1 = (key[ofs] & 0xff) << 24;
		s1 |= (key[ofs + 1] & 0xff) << 16;
		s1 |= (key[ofs + 2] & 0xff) << 8;
		s1 |= (key[ofs + 3] & 0xff);
		s2 = (key[ofs + 4] & 0xff) << 24;
		s2 |= (key[ofs + 5] & 0xff) << 16;
		s2 |= (key[ofs + 6] & 0xff) << 8;
		s2 |= (key[ofs + 7] & 0xff);
	}
	
	public void setupNonce(byte[] nonce, int ofs) throws Exception {
		
		s32 = 0x01 << (64 - 37);
		
		// xxx - confirmar
		s31 = (nonce[ofs] & 0xff) << 24;
		s31 |= (nonce[ofs + 1] & 0xff) << 16;

		int init_len = 48;
		byte init_in[] = new byte[init_len];
		byte init_out[] = new byte[init_len];
		process(init_in, 0, init_out, 0, init_len);
	}

	// xxx
	public void process(short[] inbuf, int inOfs, short[] outbuf, int outOfs,
			int len) throws Exception {

		int outEnd = outOfs + len;
		for (; outOfs < outEnd; outOfs += 1, inOfs += 1) {

			t1 = (s1 >>> 32 - 22) ^ (s1 >>> 32 - 31);
			t2 = (s2 >>> 32 - 23) ^ (s2 >>> 32 - 28);
			t3 = (s31 >>> 32 - 22) ^ ((s31 << 37 - 32) | (s32 >>> 64 - 37));

			z = t1 ^ t2 ^ t3;

			t1 ^= ((s1 >>> 32 - 30) & (s1 >>> 32 - 29))
					^ (s2 >>> 32 - 26);
			t2 ^= ((s2 >>> 32 - 27) & (s2 >>> 32 - 26))
					^ (s31 >>> 32 - 29);
			t3 ^= (((s31 << 35 - 32) | (s32 >>> 64 - 35)) & ((s31 << 36 - 32) | (s32 >>> 64 - 36)))
					^ (s1 >>> 32 - 23);

			outbuf[outOfs] = (short) (inbuf[inOfs] ^ z);

			s1 = (s1 >>> 16) | (t3 << 16);
			s2 = (s2 >>> 16) | (t1 << 16);
			s32 = (s31 << 16);
			s31 = (s31 >>> 16) | (t2 << 16);
		}
	}
	
	
}
