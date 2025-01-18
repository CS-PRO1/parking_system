package com.parking.reservation.ca;

import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import java.util.logging.Logger;

public class CertificateAuthority {

    private static final Logger LOGGER = Logger.getLogger(CertificateAuthority.class.getName());
    private KeyPair caKeyPair;

    public CertificateAuthority() {
        try {
            caKeyPair = generateCAKeyPair();
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
        signature.update(csr.getBytes());

        String signedCSR = Base64.getEncoder().encodeToString(signature.sign());
        LOGGER.info("CSR signed by CA.");
        return signedCSR;
    }

    public boolean verifyCertificate(String csr, String clientPublicKeyBase64) throws GeneralSecurityException {
        PublicKey clientPublicKey = loadClientPublicKey(clientPublicKeyBase64);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(caKeyPair.getPublic());
        signature.update(csr.getBytes());

        boolean isValid = signature.verify(Base64.getDecoder().decode(csr));
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
