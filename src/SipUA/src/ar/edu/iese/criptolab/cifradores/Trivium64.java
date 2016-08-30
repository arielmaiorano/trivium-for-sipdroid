package ar.edu.iese.criptolab.cifradores;

/**
 * Clase que implementa el algoritmo de cifrado TRIVIUM.
 * 
 * Versión usando longs (64 bits).
 * 
 */
public class Trivium64 {

	long s11, s12, s21, s22, s31, s32;
	long t1, t2, t3, z;

	public void process(byte[] inbuf, int inOfs, byte[] outbuf, int outOfs,
			int len) throws Exception {

		int outEnd = outOfs + len;
		for (; outOfs < outEnd; outOfs += 8, inOfs += 8) {
			
			t1 = ((s11 << 66 - 64) | (s12 >>> 128 - 66))
					^ ((s11 << 93 - 64) | (s12 >>> 128 - 93));
			t2 = ((s21 << 69 - 64) | (s22 >>> 128 - 69))
					^ ((s21 << 84 - 64) | (s22 >>> 128 - 84));
			t3 = ((s31 << 66 - 64) | (s32 >>> 128 - 66))
					^ ((s31 << 111 - 64) | (s32 >>> 128 - 111));
	
			z = t1 ^ t2 ^ t3;

			if (outOfs + 7 >= outEnd)
				break;

			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			outbuf[outOfs + 1] = (byte) (inbuf[inOfs + 1] ^ z >> 8);
			outbuf[outOfs + 2] = (byte) (inbuf[inOfs + 2] ^ z >> 16);
			outbuf[outOfs + 3] = (byte) (inbuf[inOfs + 3] ^ z >> 24);
			outbuf[outOfs + 4] = (byte) (inbuf[inOfs + 4] ^ z >> 32);
			outbuf[outOfs + 5] = (byte) (inbuf[inOfs + 5] ^ z >> 40);
			outbuf[outOfs + 6] = (byte) (inbuf[inOfs + 6] ^ z >> 48);
			outbuf[outOfs + 7] = (byte) (inbuf[inOfs + 7] ^ z >> 56);
			
			t1 ^= (((s11 << 91 - 64) | (s12 >>> 128 - 91)) & ((s11 << 92 - 64) | (s12 >>> 128 - 92)))
					^ ((s21 << 78 - 64) | (s22 >>> 128 - 78));
			t2 ^= (((s21 << 82 - 64) | (s22 >>> 128 - 82)) & ((s21 << 83 - 64) | (s22 >>> 128 - 83)))
					^ ((s31 << 87 - 64) | (s32 >>> 128 - 87));
			t3 ^= (((s31 << 109 - 64) | (s32 >>> 128 - 109)) & ((s31 << 110 - 64) | (s32 >>> 128 - 110)))
					^ ((s11 << 69 - 64) | (s12 >>> 128 - 69));
	
			s12 = s11;
			s11 = t3;
			s22 = s21;
			s21 = t1;
			s32 = s31;
			s31 = t2;
		}
		for (; outOfs < outEnd; outOfs++, inOfs++) {
			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			z >>= 8;
			s12 = (s12 >>> 8) | (s11 << 56);
			s11 = (s11 >>> 8) | (t3 << 56);
			s22 = (s22 >>> 8) | (s21 << 56);
			s21 = (s21 >>> 8) | (t1 << 56);
			s32 = (s32 >>> 8) | (s31 << 56);
			s31 = (s31 >>> 8) | (t2 << 56);
		}
	}

	public void setupKey(int mode, byte[] key, int ofs) throws Exception {

		s11 = (key[ofs] & 0xffL) << 56;
		s11 |= (key[ofs + 1] & 0xffL) << 48;
		s11 |= (key[ofs + 2] & 0xffL) << 40;
		s11 |= (key[ofs + 3] & 0xffL) << 32;
		s11 |= (key[ofs + 4] & 0xffL) << 24;
		s11 |= (key[ofs + 5] & 0xffL) << 16;
		s11 |= (key[ofs + 6] & 0xffL) << 8;
		s11 |= (key[ofs + 7] & 0xffL);
		s12 = (key[ofs + 8] & 0xffL) << 56;
		s12 |= (key[ofs + 9] & 0xffL) << 48;
	}

	public void setupNonce(byte[] nonce, int ofs) throws Exception {

		s32 = 0x7L << 128 - 111;

		s21 = (nonce[ofs] & 0xffL) << 56;
		s21 |= (nonce[ofs + 1] & 0xffL) << 48;
		s21 |= (nonce[ofs + 2] & 0xffL) << 40;
		s21 |= (nonce[ofs + 3] & 0xffL) << 32;
		s21 |= (nonce[ofs + 4] & 0xffL) << 24;
		s21 |= (nonce[ofs + 5] & 0xffL) << 16;
		s21 |= (nonce[ofs + 6] & 0xffL) << 8;
		s21 |= (nonce[ofs + 7] & 0xffL);
		s22 = (nonce[ofs + 8] & 0xffL) << 56;
		s22 |= (nonce[ofs + 9] & 0xffL) << 48;

		int init_len = 144;
		byte init_in[] = new byte[init_len];
		byte init_out[] = new byte[init_len];
		process(init_in, 0, init_out, 0, init_len);
	}

}
