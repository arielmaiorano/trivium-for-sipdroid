/*
 * Copyright (C) 2009 The Sipdroid Open Source Project
 * Copyright (C) 2005 Luca Veltri - University of Parma - Italy
 * 
 * This file is part of Sipdroid (http://www.sipdroid.org)
 * 
 * Sipdroid is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.sipdroid.net;

import java.net.InetAddress;
import java.net.DatagramPacket;
import java.security.MessageDigest;
import java.io.IOException;

// xxx
import org.sipdroid.sipua.ui.CallScreen;
import ar.edu.iese.criptolab.cifradores.TriviumToy32;
import android.util.Log;

/**
 * RtpSocket implements a RTP socket for receiving and sending RTP packets.
 * <p>
 * RtpSocket is associated to a DatagramSocket that is used to send and/or
 * receive RtpPackets.
 */
public class RtpSocket {
	/** UDP socket */
	SipdroidSocket socket;
	DatagramPacket datagram;

	/** Remote address */
	InetAddress r_addr;

	/** Remote port */
	int r_port;

	// xxx
	TriviumToy32 triviumSend = null;
	TriviumToy32 triviumRecv = null;
	int triviumSendCounter = 0;
	int triviumRecvCounter = 0;

	/** Creates a new RTP socket (only receiver) */
	public RtpSocket(SipdroidSocket datagram_socket) {
		socket = datagram_socket;
		r_addr = null;
		r_port = 0;
		datagram = new DatagramPacket(new byte[1], 1);
	}

	/** Creates a new RTP socket (sender and receiver) */
	public RtpSocket(SipdroidSocket datagram_socket,
			InetAddress remote_address, int remote_port) {
		socket = datagram_socket;
		r_addr = remote_address;
		r_port = remote_port;
		datagram = new DatagramPacket(new byte[1], 1);
	}

	/** Returns the RTP SipdroidSocket */
	public SipdroidSocket getDatagramSocket() {
		return socket;
	}

	/** Receives a RTP packet from this socket */
	public void receive(RtpPacket rtpp) throws IOException {
		datagram.setData(rtpp.packet);
		datagram.setLength(rtpp.packet.length);
		socket.receive(datagram);
		if (!socket.isConnected())
			socket.connect(datagram.getAddress(), datagram.getPort());
		rtpp.packet_len = datagram.getLength();

		// xxx
		if (CallScreen.encryptionOn) {
			try {
				if (triviumRecv == null) {
					MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
					byte[] passBytes = CallScreen.encryptionPassword
							.getBytes("UTF-8");
					byte[] passHash = sha256.digest(passBytes);
					triviumRecv = new TriviumToy32();
					triviumRecv.setupKey(0, passHash, 0);
					triviumRecv.setupNonce(passHash, 10);
					triviumRecvCounter = 0;
				}
				int hLen = rtpp.getHeaderLength();
				int pLen = rtpp.getPayloadLength();
				//Log.e("RECV", " pLen == " +  pLen);
				//Log.e("RECV", " rtpp.packet[hLen + 4] == " +  rtpp.packet[hLen + 4]);
				//Log.e("RECV", " rtpp.getPayloadType() == " +  rtpp.getPayloadType());
				if (pLen > 0 && rtpp.packet[hLen + 4] == 0
						&& rtpp.getPayloadType() == 8) {
					int tmpRecvCounter = 0;
					tmpRecvCounter |= (rtpp.packet[hLen + 0] & 0xff) << 24;
					tmpRecvCounter |= (rtpp.packet[hLen + 1] & 0xff) << 16;
					tmpRecvCounter |= (rtpp.packet[hLen + 2] & 0xff) << 8;
					tmpRecvCounter |= (rtpp.packet[hLen + 3] & 0xff) << 0;
					int diffCounter = tmpRecvCounter - triviumRecvCounter;
					//Log.e("RECV", " diffCounter == " +  diffCounter);
					if (tmpRecvCounter > 0 && diffCounter > 0
							&& diffCounter < 2000000) {
						byte[] tmp = new byte[diffCounter];
						triviumRecv.process(tmp, 0, tmp, 0, tmp.length);
						triviumRecvCounter += diffCounter;
					}
					/*
					if (tmpRecvCounter > 0 && diffCounter > 0
							&& diffCounter < 10*1024*1024) {
						byte[] tmp = new byte[100 * 1024];
						while (diffCounter != 0)	{
							int n = diffCounter <= (100 * 1024) ? diffCounter : (100 * 1024); 
							triviumRecv.process(tmp, 0, tmp, 0, n);
							triviumRecvCounter += n;
							diffCounter -= n;
						}
					}
					*/
					
					if (triviumRecvCounter == tmpRecvCounter) {
						triviumRecv.process(rtpp.packet, hLen, rtpp.packet,
								hLen, pLen);
						triviumRecvCounter += pLen;
						rtpp.packet[hLen + 0] = -43;
						rtpp.packet[hLen + 1] = -43;
						rtpp.packet[hLen + 2] = -43;
						rtpp.packet[hLen + 3] = -43;
						rtpp.packet[hLen + 4] = -43;
					}
				}
			} catch (Exception e) {
				Log.e(this.getClass().getName(), e.toString());
			}
		}

	}

	/** Sends a RTP packet from this socket */
	public void send(RtpPacket rtpp) throws IOException {

		// xxx
		if (CallScreen.encryptionOn) {
			try {
				if (triviumSend == null) {
					MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
					byte[] passBytes = CallScreen.encryptionPassword
							.getBytes("UTF-8");
					byte[] passHash = sha256.digest(passBytes);
					triviumSend = new TriviumToy32();
					triviumSend.setupKey(0, passHash, 0);
					triviumSend.setupNonce(passHash, 10);
					triviumSendCounter = 0;
				}
				int hLen = rtpp.getHeaderLength();
				int pLen = rtpp.getPayloadLength();
				if (pLen > 0 && rtpp.getPayloadType() == 8) {
					triviumSend.process(rtpp.packet, hLen, rtpp.packet, hLen,
							pLen);
					rtpp.packet[hLen + 0] = (byte) ((triviumSendCounter >>> 24) & 0xff);
					rtpp.packet[hLen + 1] = (byte) ((triviumSendCounter >>> 16) & 0xff);
					rtpp.packet[hLen + 2] = (byte) ((triviumSendCounter >>> 8) & 0xff);
					rtpp.packet[hLen + 3] = (byte) ((triviumSendCounter) & 0xff);
					rtpp.packet[hLen + 4] = 0;
					triviumSendCounter += pLen;
				}
			} catch (Exception e) {
				Log.e(this.getClass().getName(), e.toString());
			}
		}

		datagram.setData(rtpp.packet);
		datagram.setLength(rtpp.packet_len);
		datagram.setAddress(r_addr);
		datagram.setPort(r_port);
		socket.send(datagram);
	}

	/** Closes this socket */
	public void close() { // socket.close();
	}

}
