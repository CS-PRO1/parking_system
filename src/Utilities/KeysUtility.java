package Utilities;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class KeysUtility {

    // Generates an RSA key pair with a key size of 2048 bits.
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    // Generates a Diffie-Hellman key pair with a key size of 2048 bits.
    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator dhKeyPairGen = KeyPairGenerator.getInstance("DH");
        dhKeyPairGen.initialize(2048);
        return dhKeyPairGen.generateKeyPair();
    }

    // Generates a session key encrypted using the Diffie-Hellman key protocol.
    public static SecretKey generateSessionKey(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }
}