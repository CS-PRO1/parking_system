package utilities;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class CertificateAuthority {

    private static final Logger LOGGER = Logger.getLogger(CertificateAuthority.class.getName());
    private KeyPair caKeyPair;

    public CertificateAuthority() {
        try {
            caKeyPair = generateCAKeyPair();
            LOGGER.info("CA Key Pair generated.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.severe("Failed to generate CA KeyPair: " + e.getMessage());
        }
    }

    private KeyPair generateCAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    public String signCSR(String csr) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(caKeyPair.getPrivate());
        signature.update(Base64.getDecoder().decode(csr)); // Decode the Base64 string back to bytes

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verifyCertificate(String signedCSR, PublicKey clientPublicKey) throws GeneralSecurityException {
        LOGGER.info("Verifying certificate with CA public key.");
        LOGGER.info("Received signed certificate: " + signedCSR);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(caKeyPair.getPublic());
        signature.update(clientPublicKey.getEncoded()); // Update with the public key bytes

        boolean isValid = signature.verify(Base64.getDecoder().decode(signedCSR));
        LOGGER.info("Certificate verification result: " + isValid);
        return isValid;
    }

    private PublicKey loadClientPublicKey(String clientPublicKeyBase64) throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(clientPublicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public PublicKey getCAPublicKey() {
        return caKeyPair.getPublic();
    }
}
