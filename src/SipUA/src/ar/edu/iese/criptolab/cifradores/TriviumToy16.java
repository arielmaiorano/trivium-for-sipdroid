package ar.edu.iese.criptolab.cifradores;

/**
 * Clase que implementa el algoritmo de cifrado TRIVIUM TOY.
 * 
 * Versión usando shorts -en realidad chars, porque estos
 * son unsigned- (16 bits).
 * 
 */
public class TriviumToy16 {

	char s11, s12, s21, s22, s31, s32, s33;
	char t1, t2, t3, z;

	public void process(byte[] inbuf, int inOfs, byte[] outbuf, int outOfs,
			int len) throws Exception {

		int outEnd = outOfs + len;
		for (; outOfs < outEnd; outOfs += 2, inOfs += 2) {
			
			t1 = (char) (((s11 << 22 - 16) | (s12 >>> 32 - 22))
					^ ((s11 << 31 - 16) | (s12 >>> 32 - 31)));
			t2 = (char) (((s21 << 23 - 16) | (s22 >>> 32 - 23))
					^ ((s21 << 28 - 16) | (s22 >>> 32 - 28)));
			t3 = (char) (((s31 << 22 - 16) | (s32 >>> 32 - 22))
					^ ((s32 << 37 - 32) | (s33 >>> 48 - 37)));

			z = (char) (t1 ^ t2 ^ t3);
	
			t1 ^= (((s11 << 30 - 16) | (s12 >>> 32 - 30)) & ((s11 << 29 - 16) | (s12 >>> 32 - 29)))
					^ ((s21 << 26 - 16) | (s22 >>> 32 - 26));
			t2 ^= (((s21 << 27 - 16) | (s22 >>> 32 - 27)) & ((s21 << 26 - 16) | (s22 >>> 32 - 26)))
					^ ((s31 << 29 - 16) | (s32 >>> 32 - 29));
			t3 ^= (((s32 << 35 - 32) | (s33 >>> 48 - 35)) & ((s32 << 36 - 32) | (s33 >>> 48 - 36)))
					^ ((s11 << 23 - 16) | (s12 >>> 32 - 23));

			if (outOfs + 1 >= outEnd)
				break;

			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			outbuf[outOfs + 1] = (byte) (inbuf[inOfs + 1] ^ z >> 8);

			s12 = s11;
			s11 = t3;
			s22 = s21;
			s21 = t1;
			s33 = s32;
			s32 = s31;
			s31 = t2;
		}

		for (; outOfs < outEnd; outOfs++, inOfs++) {
			outbuf[outOfs] = (byte) (inbuf[inOfs] ^ z);
			z >>= 8;
			s12 = (char) ((s12 >>> 8) | (s11 << 8));
			s11 = (char) ((s11 >>> 8) | (t3 << 8));
			s22 = (char) ((s22 >>> 8) | (s21 << 8));
			s21 = (char) ((s21 >>> 8) | (t1 << 8));
			s33 = (char) ((s33 >>> 8) | (s32 << 8));
			s32 = (char) ((s32 >>> 8) | (s31 << 8));
			s31 = (char) ((s31 >>> 8) | (t2 << 8));
		}
	}

	public void setupKey(int mode, byte[] key, int ofs) throws Exception {

		// xxx - confirmar
		s11 = (char) ((key[ofs] & 0xff) << 8);
		s11 |= (char) ((key[ofs + 1] & 0xff));
		s12 = (char) ((key[ofs + 2] & 0xff) << 8);
		s12 |= (char) ((key[ofs + 3] & 0xff));
		s21 = (char) ((key[ofs + 4] & 0xff) << 8);
		s21 |= (char) ((key[ofs + 5] & 0xff));
		s22 = (char) ((key[ofs + 6] & 0xff) << 8);
		s22 |= (char) ((key[ofs + 7] & 0xff));
	}

	public void setupNonce(byte[] nonce, int ofs) throws Exception {
		
		s33 = (short) (0x01 << (48 - 37));

		// xxx - confirmar
		s31 = (char) ((nonce[ofs] & 0xff) << 8);
		s31 |= (char) ((nonce[ofs + 1] & 0xff));

		int init_len = 48;
		byte init_in[] = new byte[init_len];
		byte init_out[] = new byte[init_len];
		process(init_in, 0, init_out, 0, init_len);
	}

}
