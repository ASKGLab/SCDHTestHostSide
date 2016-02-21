/*
 * 3-Clause BSD License
 * Copyright (c) 2016, Thotheolh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and
 * /or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 * may be used to endorse or promote products derived from this software without 
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
package scdhtesthostside;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Thotheolh
 */
public class SCDHTestHostSide {

    /**
     * @param args the command line arguments
     */
    private static final byte[] SELECT_APDU = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x05, (byte) 0xED, (byte) 0xE4, (byte) 0xFB, (byte) 0xEB, (byte) 0x9E};
    private static final byte[] CARD_INIT_DH = new byte[]{(byte) 0xB0, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final byte[] CARD_GET_Y = new byte[]{(byte) 0xB0, (byte) 0x11, (byte) 0x01, (byte) 0x00, (byte) 0x00};
    private static final byte[] CARD_SET_Y = new byte[]{(byte) 0xB0, (byte) 0x12, (byte) 0x01, (byte) 0x00, (byte) 0xFF};
    private static final byte[] CARD_DH_FINALIZE = new byte[]{(byte) 0xB0, (byte) 0x1F, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final byte[] CARD_DH_TEST = new byte[]{(byte) 0xB0, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x10};
    private static final String DH_GRP_14_P_STR = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            + "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            + "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            + "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            + "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            + "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            + "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            + "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
            .replaceAll("\\s", "");
    public static final byte[] reply = {(byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c,
        (byte) 0x6f, (byte) 0x20, (byte) 0x4a, (byte) 0x61, (byte) 0x76, (byte) 0x61,
        (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x2e};
    private static final BigInteger DH_GRP_14_P = new BigInteger(DH_GRP_14_P_STR, 16);
    private static final BigInteger DH_GRP_14_G = BigInteger.valueOf(2L);
    private static StringBuilder DH_GRP_14_Y_STR = new StringBuilder();
    private static BigInteger DH_GRP_14_Y = null;
    private static ResponseAPDU r = null;
    private static byte[] hexBytes = new byte[257];
    private static SecretKeySpec cryptKeySpec;
    private static Cipher aesCipher;
    private static int ctr = 0;

    public static void main(String[] args) {
        try {
            // show the list of available terminals
            Scanner sc = new Scanner(System.in);
            TerminalHandler cardTerminals = new TerminalHandler();
            cardTerminals.loadDefaultTerminal();
            cardTerminals.printTerminalInfo(cardTerminals.getTerminals());
            System.out.print("Please enter Terminal ID: ");
            int terminalId = Integer.valueOf(sc.next());
            Card card = cardTerminals.getCard(TerminalHandler.CARD_PROTO_ANY, terminalId);
            System.out.println("\tcard: " + card);
            CardChannel channel = card.getBasicChannel();

            // Selecting card applet and getting ATR response
            byte[] baATR = card.getATR().getBytes();
            System.out.println("ATR: " + CardUtils.toHexString(baATR));
            System.out.println("Selecting Applet...");
            System.out.println("Send: " + CardUtils.toHexString(SELECT_APDU));
            r = channel.transmit(new CommandAPDU(SELECT_APDU));
            System.out.println("Response: " + CardUtils.toHexString(r.getBytes()));

            // Begin DH negotiation
            System.out.println("Starting Diffie-Hellman negotiation using Diffie-Hellman Group 14 from RFC-3526 with G=2...");
            KeyPairGenerator hostKeyGen = KeyPairGenerator.getInstance("DH");
            KeyAgreement dhAlgo = KeyAgreement.getInstance("DH");
            DHParameterSpec dhGrp14KeySpec = new DHParameterSpec(DH_GRP_14_P, DH_GRP_14_G);
            System.out.println("\tUsing P value (" + DH_GRP_14_P.bitLength() + "): " + dhGrp14KeySpec.getP());
            System.out.println("\tUsing G value (" + DH_GRP_14_G.bitLength() + "): " + dhGrp14KeySpec.getG());
            hostKeyGen.initialize(dhGrp14KeySpec);

            // Create Host DH private key
            System.out.println("Creating Host DH private key...");
            KeyPair hostKey = hostKeyGen.generateKeyPair();
            DHPublicKey hostPublic = (DHPublicKey) hostKey.getPublic();
            System.out.println("Get host Y value (" + hostPublic.getY().bitLength() + "): " + hostPublic.getY());
            System.out.println("Host Y bytes (" + hostPublic.getY().toByteArray().length + "): " + CardUtils.toHexString(hostPublic.getY().toByteArray()));

            // Announcing to card side to do INIT() on card's DH
            System.out.println("Init Smart Card DH Algo...");
            r = channel.transmit(new CommandAPDU(CARD_INIT_DH));
            System.out.println("Response: " + CardUtils.toHexString(r.getBytes()));

            // Get card side Y value
            System.out.println("Get card Y value...");
            r = channel.transmit(new CommandAPDU(CARD_GET_Y));
            System.arraycopy(r.getData(), 0, hexBytes, 1, r.getData().length);
            System.out.println("Response(" + r.getData().length * 8 + "): " + CardUtils.toHexString(r.getData()));
//            System.out.println("Response(" + r.getBytes().length * 8 + "): " + CardUtils.toHexString(r.getBytes()));
            DH_GRP_14_Y = new BigInteger(hexBytes);
            DHPublicKey cardPubKey = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(new DHPublicKeySpec(DH_GRP_14_Y, DH_GRP_14_P, DH_GRP_14_G));
            System.out.println("Card Y value (" + DH_GRP_14_Y.bitLength() + "): " + cardPubKey.getY());
            dhAlgo.init(hostKey.getPrivate());
            dhAlgo.doPhase(cardPubKey, true);

            // Set host Y value to card
            System.out.println("Set host Y value...");
            hexBytes = new byte[261];

            // Removes the 0x00 signed byte from host Y bytes if more than 257 because 257 means signed byte at pos 0
            if (hostPublic.getY().toByteArray().length > 256) {
                ctr = 1;
            } else {
                ctr = 0;
            }

            // Offset to remove signed byte from host Y bytes if exist by shifting pos by 1
            System.arraycopy(CARD_SET_Y, 0, hexBytes, 0, CARD_SET_Y.length);
            System.arraycopy(hostPublic.getY().toByteArray(), ctr, hexBytes, 5, 256);
            System.out.println("Sending APDU (" + hexBytes.length + "): " + CardUtils.toHexString(hexBytes));
            r = channel.transmit(new CommandAPDU(hexBytes));
            System.out.println("Response(" + r.getBytes().length * 8 + "): " + CardUtils.toHexString(r.getBytes()));

            // Finalize card side
            System.out.println("Finalize DH on card side...");
            r = channel.transmit(new CommandAPDU(CARD_DH_FINALIZE));
            System.out.println("Response(" + r.getBytes().length + "): " + CardUtils.toHexString(r.getBytes()));

            // Generate AES crypto key from shared secret
            byte[] sessDHSecret = dhAlgo.generateSecret();
            byte[] aesKey = new byte[16];
            System.arraycopy(sessDHSecret, 0, aesKey, 0, 16);

            // DH Crypto Test
            cryptKeySpec = new SecretKeySpec(aesKey, "AES");
            System.out.println("Test Card AES Crypto...");
            r = channel.transmit(new CommandAPDU(CARD_DH_TEST));
            hexBytes = r.getData();
            System.out.println("Response(" + r.getBytes().length + "): " + CardUtils.toHexString(r.getBytes()));

            // 2 bytes return usually indicates error SW
            if (r.getBytes().length > 2) {
                aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
                aesCipher.init(Cipher.DECRYPT_MODE, cryptKeySpec);
                byte[] decryptResult = aesCipher.doFinal(hexBytes);
                System.out.println("Test Decrypted: " + CardUtils.toHexString(decryptResult));
                System.out.println("Test Answer " + CardUtils.toHexString(reply));
                if (Arrays.equals(reply, decryptResult)) {
                    System.out.println("DH Test Succeeded :)");
                } else {
                    System.out.println("Failed DH Test !!! \n Decryption results are not the same !!!");
                }
            } else {
                System.out.println("Failed DH Test !!! \n Returned bytes are too short to be encrypted test results !!!");
            }
        } catch (CardException |
                NoSuchAlgorithmException |
                InvalidAlgorithmParameterException |
                NoSuchPaddingException |
                InvalidKeyException |
                IllegalStateException |
                InvalidKeySpecException |
                IllegalBlockSizeException |
                BadPaddingException ex) {
            Logger.getLogger(SCDHTestHostSide.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
