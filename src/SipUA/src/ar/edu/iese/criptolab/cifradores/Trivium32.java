package ar.edu.iese.criptolab.cifradores;

/**
 * Clase que implementa el algoritmo de cifrado TRIVIUM.
 * 
 * Versión usando ints (32 bits).
 * 
 */
public class Trivium32 {

	int s11, s12, s13, s21, s22, s23, s31, s32, s33, s34;
	int t1, t2, t3, z;

	public void process(byte[] inbuf, int inOfs, byte[] outbuf, int outOfs,
			int len) throws Exception {

		int outEnd = outOfs + len;
		for (; outOfs < outEnd; outOfs += 4, inOfs += 4) {

			t1 = ((s12 << 66 - 64) | (s13 >>> 96 - 66))
					^ ((s12 << 93 - 64) | (s13 >>> 96 - 93));
			t2 = ((s22 << 69 - 64) | (s23 >>> 96 - 69))
					^ ((s22 << 84 - 64) | (s23 >>> 96 - 84));
			t3 = ((s32 << 66 - 64) | (s33 >>> 96 - 66))
					^ ((s33 << 111 - 96) | (s34 >>> 128 - 111));

			z = t1 ^ t2 ^ t3;

			t1 ^= (((s12 << 91 - 64) | (s13 >>> 96 - 91)) & ((s12 << 92 - 64) | (s13 >>> 96 - 92)))
					^ ((s22 << 78 - 64) | (s23 >>> 96 - 78));
			t2 ^= (((s22 << 82 - 64) | (s23 >>> 96 - 82)) & ((s22 << 83 - 64) | (s23 >>> 96 - 83)))
					^ ((s32 << 87 - 64) | (s33 >>> 96 - 87));
			t3 ^= (((s33 << 109 - 96) | (s34 >>> 128 - 109)) & ((s33 << 110 - 96) | (s34 >>> 128 - 110)))
					^ ((s12 << 69 - 64) | (s13 >>> 96 - 69));

			if (outOfs + 3 >= outEnd)
				break;

			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			outbuf[outOfs + 1] = (byte) (inbuf[inOfs + 1] ^ z >> 8);
			outbuf[outOfs + 2] = (byte) (inbuf[inOfs + 2] ^ z >> 16);
			outbuf[outOfs + 3] = (byte) (inbuf[inOfs + 3] ^ z >> 24);

			s13 = s12;
			s12 = s11;
			s11 = t3;
			s23 = s22;
			s22 = s21;
			s21 = t1;
			s34 = s33;
			s33 = s32;
			s32 = s31;
			s31 = t2;
		}
		
		for (; outOfs < outEnd; outOfs++, inOfs++) {
			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			z >>= 8;
			s13 = (s13 >>> 8) | (s12 << 24);
			s12 = (s12 >>> 8) | (s11 << 24);
			s11 = (s11 >>> 8) | (t3 << 24);
			s23 = (s23 >>> 8) | (s22 << 24);
			s22 = (s22 >>> 8) | (s21 << 24);
			s21 = (s21 >>> 8) | (t1 << 24);
			s34 = (s34 >>> 8) | (s33 << 24);
			s33 = (s33 >>> 8) | (s32 << 24);
			s32 = (s32 >>> 8) | (s31 << 24);
			s31 = (s31 >>> 8) | (t2 << 24);
		}
	}

	public void setupKey(int mode, byte[] key, int ofs) throws Exception {

		s11 = (key[ofs] & 0xff) << 24;
		s11 |= (key[ofs + 1] & 0xff) << 16;
		s11 |= (key[ofs + 2] & 0xff) << 8;
		s11 |= (key[ofs + 3] & 0xff);
		s12 = (key[ofs + 4] & 0xff) << 24;
		s12 |= (key[ofs + 5] & 0xff) << 16;
		s12 |= (key[ofs + 6] & 0xff) << 8;
		s12 |= (key[ofs + 7] & 0xff);
		s13 = (key[ofs + 8] & 0xff) << 24;
		s13 |= (key[ofs + 9] & 0xff) << 16;
	}

	public void setupNonce(byte[] nonce, int ofs) throws Exception {

		s34 = 0x07 << (128 - 111);

		s21 = (nonce[ofs] & 0xff) << 24;
		s21 |= (nonce[ofs + 1] & 0xff) << 16;
		s21 |= (nonce[ofs + 2] & 0xff) << 8;
		s21 |= (nonce[ofs + 3] & 0xff);
		s22 = (nonce[ofs + 4] & 0xff) << 24;
		s22 |= (nonce[ofs + 5] & 0xff) << 16;
		s22 |= (nonce[ofs + 6] & 0xff) << 8;
		s22 |= (nonce[ofs + 7] & 0xff);
		s23 = (nonce[ofs + 8] & 0xff) << 24;
		s23 |= (nonce[ofs + 9] & 0xff) << 16;

		int init_len = 144;
		byte init_in[] = new byte[init_len];
		byte init_out[] = new byte[init_len];
		process(init_in, 0, init_out, 0, init_len);
	}

}
