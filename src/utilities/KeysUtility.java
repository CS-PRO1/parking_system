import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class KeysUtility {

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator dhKeyPairGen = KeyPairGenerator.getInstance("DH");
        dhKeyPairGen.initialize(2048);
        return dhKeyPairGen.generateKeyPair();
    }

    public static SecretKey generateSessionKey(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }
}
