package simpleapdu;

import applets.SimpleApplet;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;



 

public class SimpleAPDU 
{
    static CardMngr cardManager = new CardMngr();
    
    //ECDH Parameters
    static byte[] baTempA = new byte[17];
    static byte[] baTempB = new byte[17];
    static byte[] baTempP = new byte[17];
    static byte[] baTempW = new byte[33];
    static byte[] baTempS = new byte[17];
    static byte[] baTempSS = new byte[17];
    static byte[] baTempSS1 = new byte[17];
    static short lenA, lenB, lenP, lenW, lenS, lenSS;
    static KeyPair kpV;
    static ECPrivateKey privKeyV;
    static ECPublicKey pubKeyV;
    static KeyAgreement ecdhV;
    private static byte baPrivKeyV[] = new byte[17];
    private static byte baPubKeyV[] = new byte[17];
    static private byte baPubKeyU[] = new byte[17];
    static String pin;
    static byte[] hashBuffer = new byte[20];
    
    private static final byte APPLET_AID[] = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x06, (byte) 0xC9, (byte) 0xAA, (byte) 0x4E, (byte) 0x15, (byte) 0xB3, (byte) 0xF6, (byte) 0x7F};

    
    // helper functions for SPEKE calculations [IEE163] [https://github.com/chetan51/ABBC/blob/master/src/main/java/RSAEngine/Crypter.java]
    public static BigInteger OS2IP(byte[]X){
		BigInteger out = new BigInteger("0");
		BigInteger twofiftysix = new BigInteger("256");
		
		for(int i = 1; i <= X.length; i++){
			out = out.add((BigInteger.valueOf(0xFF & X[i - 1])).multiply(twofiftysix.pow(X.length-i)));
		}
		//x = x(xLen–1)^256xLen–1 + x(xLen–2)^256xLen–2 + … + x(1)^256 + x0
		
		return out;
	}

    
    public static byte[] I2OSP(BigInteger X, int XLen){
		BigInteger twofiftysix = new BigInteger("256");
		byte[] out = new byte[XLen];
		BigInteger[] cur;
		
		if(X.compareTo(twofiftysix.pow(XLen)) >= 0){
			return new String("integer too large").getBytes();
		}
		for(int i = 1; i <= XLen; i++){
			cur = X.divideAndRemainder(twofiftysix.pow(XLen-i));
			//X = cur[1];
			out[i - 1] = cur[0].byteValue();
		}
		//basically the inverse of the above
		//Cur is an array of two bigints, with cur[0]=X/256^(XLen-i) and cur[1]=X/256^[XLen-i]
		
		return out;
	}
    
    
    public static void main(String[] args) throws Exception 
    {
        byte[] installData = new byte[10];
        cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            
        String data = javax.xml.bind.DatatypeConverter.printHexBinary(APPLET_AID);
        System.out.println(data);
        System.out.println(CardMngr.bytesToHex(APPLET_AID));

        ecdh();
    }    
    
    public static void ecdh() throws Exception
    {
        System.out.println("********************V parameters (PC Side)********************");
            
        InputStreamReader r = new InputStreamReader(System.in);
        BufferedReader br = new BufferedReader(r);
        System.out.println("Enter PIN (PC): ");
        pin= br.readLine();
        System.out.print("PIN (PC): " + pin);
        System.out.println();
            
        if(pin.compareTo("1234") != 0)
        {
            System.out.println("Invalid PIN");
            System.exit(0);
        }
        
        if(pin.length() != 4 || !pin.matches("[0-9]+"))
        {
            System.out.println("Invalid PIN");
            System.exit(0);
        }
            
        MessageDigest m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
        m_hash.doFinal(pin.getBytes(),(short)0,(short)pin.getBytes().length,hashBuffer,(short)0);
        System.out.print("HASH OF PIN: ");
        for (byte b: hashBuffer) System.out.print(String.format("%X",b));
        System.out.println();
                    
        kpV = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_128);
        kpV.genKeyPair();
        privKeyV = (ECPrivateKey) kpV.getPrivate();
        pubKeyV = (ECPublicKey) kpV.getPublic();
        
        System.out.println("Key Pair Generation (V)");
        lenA = pubKeyV.getA(baTempA,(short) 0); 
        System.out.print("A (V) " + lenA + " :"); 
        for (byte b: baTempA) System.out.print(String.format("%02X", b)); 
            
        System.out.println();
        lenB = pubKeyV.getB(baTempB,(short) 0); 
        System.out.print("B (V) " + lenB + " :"); 
        for (byte b: baTempB) System.out.print(String.format("%02X", b));
        
        System.out.println();
        lenP = pubKeyV.getField(baTempP, (short) 0); 
        System.out.print("P (V) " + lenP + " :"); 
        for (byte b: baTempP) System.out.print(String.format("%02X", b));
            
        System.out.println();
        lenW = pubKeyV.getW(baTempW,(short) 0); 
        System.out.print("Public Key (V) " + lenW + " :"); 
        for (byte b: baTempW) System.out.print(String.format("%02X", b));

        System.out.println();
        lenS = privKeyV.getS(baTempS,(short) 0);
        System.out.print("Private Key (V) " + lenS + " :");
        for (byte b: baTempS) System.out.print(String.format("%02X", b));
        System.out.println();
            
        byte pu[] = new byte[CardMngr.HEADER_LENGTH];
        pu[CardMngr.OFFSET_CLA] = (byte) 0x00;
        pu[CardMngr.OFFSET_INS] = (byte) 0xD1;
        pu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pu[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] pus = cardManager.sendAPDUSimulator(pu);
        baPubKeyU = Arrays.copyOfRange(pus, 0, 33);
        System.out.println();
        System.out.print("Public Key Received from Card (U) " + baPubKeyU.length + " :");
        for (byte b: baPubKeyU) System.out.print(String.format("%02X", b));
        System.out.println();
            
        byte ss[] = new byte[CardMngr.HEADER_LENGTH + lenW];
        ss[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss[CardMngr.OFFSET_INS] = (byte) 0xD2;
        ss[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(baTempW, 0, ss, 5, lenW);
        byte[] sss = cardManager.sendAPDUSimulator(ss);
        baTempSS1 = Arrays.copyOfRange(sss, 0, 17);
        System.out.println();
        System.out.print("Shared Secret Received from Card (U) " + baTempSS1.length + " :");
        for (byte b: baTempSS1) System.out.print(String.format("%02X", b));
        System.out.println();
            
        Util.arrayCopyNonAtomic(baTempS, (short) 0, baPrivKeyV, (short) 0, (short) lenS);
        
        ecdhV = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, true);
        ecdhV.init(privKeyV);
        lenSS = ecdhV.generateSecret(baPubKeyU, (short)0, lenW, baTempSS, (short) 0);
        System.out.println();
        System.out.print("Shared Secred U and V (V) " + lenSS + " :");
        for (byte b: baTempSS) System.out.print(String.format("%02X", b));
        System.out.println();
            
        System.out.println("Shared Secret Equality: " + Arrays.equals(baTempSS, baTempSS1));
        System.out.println();
        
        //if(Arrays.equals(baTempSS, baTempSS1) == true)
        //start();
        //
        //BigInteger G_number = OS2IP(hashBuffer).mod(p);
        //U = G.pow(A).mod(P)
        //V = G.pow(B).mod(P)
        //
        
        aes();
    }
}
