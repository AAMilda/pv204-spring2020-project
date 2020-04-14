package applets;

import javacard.framework.*;
import javacard.security.*;

public class SimpleApplet extends javacard.framework.Applet 
{
    byte[] baTemp = new byte[255];
    short len;
    
    byte[] baPrivKeyU, baPubKeyU, baPubKeyV;
    byte[] baTempA = new byte[17];
    byte[] baTempB = new byte[17];
    byte[] baTempP = new byte[17];
    byte[] baTempW = new byte[33];
    byte[] baTempS = new byte[33];
    byte[] baTempSS = new byte[17];
    short lenA, lenB, lenP, lenW, lenS, lenSS;
    KeyPair kpU;
    ECPrivateKey privKeyU;
    ECPublicKey pubKeyU;
    KeyAgreement ecdhU;
    private final MessageDigest m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);

    final static byte CLA_SIMPLEAPPLET = (byte) 0x00;

    protected SimpleApplet(byte[] buffer, short offset, byte length) {register();}
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {SimpleApplet simpleApplet = new SimpleApplet(bArray, bOffset, bLength);}
    public boolean select() {return true;}
    public void deselect() {}

    public void process(APDU apdu) throws ISOException 
    {
        byte[] apduBuffer = apdu.getBuffer();
        if (selectingApplet())  return;
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) 
        {
                switch (apduBuffer[ISO7816.OFFSET_INS]) 
                {
                    case (byte) 0xD1: processINSD1(apdu); return;
                    default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
                }
            } 
        else
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    private void processINSD1(APDU apdu)
    {
        System.out.println("********************U parameters (Card Side)********************");

        byte pin[] = {0x31,0x32,0x33,0x34};
        System.out.print("PIN Set on Card: 1234");
        System.out.println();
        byte[] hashBuffer = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_RESET);
        m_hash.doFinal(pin,(short)0,(short)pin.length,hashBuffer,(short)0);
        System.out.print("HASH OF PIN: ");
        for (byte b:hashBuffer) System.out.print(String.format("%X",b));
        System.out.println();
        //String hashpin = toHexString(getSHA(pin));
        //System.out.println("PIN HASH (PC): " + hashpin);
    
        /*int p = 5; // safeprime p
        int b = 4; // random b
        //g = hash(pin^2)mod p
        //to a = g^b mod p
        int pinn = Integer.valueOf(pin);
        int pinsq = (int) Math.pow(pinn, 2);
        String pinha = toHexString(getSHA(Integer.toString(pinsq)));
        int pinhai = Integer.valueOf(pinha);
        int g = pinhai % p;
        int sendtoa = (int) (Math.pow(g, b) % p);*/

        
        
        
        kpU = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_128);
        kpU.genKeyPair();
        privKeyU = (ECPrivateKey) kpU.getPrivate();
        pubKeyU = (ECPublicKey) kpU.getPublic();

        System.out.println("Key Pair Generation (U)");
        lenA = pubKeyU.getA(baTempA,(short) 0);
        System.out.print("A (U) " + lenA + " :"); 
        for (byte b: baTempA) System.out.print(String.format("%02X", b)); 

        System.out.println();
        lenB = pubKeyU.getB(baTempB,(short) 0);
        System.out.print("B (U) " + lenB + " :"); 
        for (byte b: baTempB) System.out.print(String.format("%02X", b));

        System.out.println();
        lenP = pubKeyU.getField(baTempP, (short) 0);
        System.out.print("P (U) " + lenP + " :"); 
        for (byte b: baTempP) System.out.print(String.format("%02X", b));
        
        System.out.println();
        lenW = pubKeyU.getW(baTempW,(short) 0);
        System.out.print("Public Key (U) " + lenW + " :"); 
        for (byte b: baTempW) System.out.print(String.format("%02X", b));
       
        lenS = privKeyU.getS(baTempS,(short) 0);
        baPrivKeyU =new byte[lenS];
        Util.arrayCopyNonAtomic(baTempS, (short)0, baPrivKeyU, (short)0, lenS);
        System.out.println();
        System.out.print("Private Key (U) " + lenS + " :");
        for (byte b: baPrivKeyU) System.out.print(String.format("%02X", b));
        System.out.println();       
        
        /*ecdhU = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH,false);
        ecdhU.init(privKeyU);
        lenSS = ecdhU.generateSecret(baPubKeyV,(short)0, lenW, baTempSS, (short)0);
                System.out.println();
        System.out.print("Shared Secret (U) " + lenSS + " :");
        for (byte b: baTempSS)
            System.out.print(String.format("%02X", b));
        System.out.println();*/
    }
}