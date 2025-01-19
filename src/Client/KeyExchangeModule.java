package Client;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

import Utilities.EncryptionUtility;
import Utilities.KeysUtility;

import java.util.logging.Logger;

public class KeyExchangeModule {
    private static final Logger LOGGER = Logger.getLogger(KeyExchangeModule.class.getName());
    private PublicKey serverPublicKey;
    private SecretKey sessionKey;
    private PrivateKey clientPrivateKey;
    private PublicKey clientPublicKey;

    // Performs the key generation process and the handshake procedure between the
    // server and the client
    public void performKeyExchange(Socket socket, ObjectOutputStream out, ObjectInputStream in) throws Exception {
        KeyPair clientKeyPair = KeysUtility.generateRSAKeyPair();
        clientPublicKey = clientKeyPair.getPublic();
        clientPrivateKey = clientKeyPair.getPrivate();
        serverPublicKey = (PublicKey) in.readObject();
        LOGGER.info("Received server's public key.");
        out.writeObject(clientPublicKey);
        out.flush(); // Ensure the data is sent now
        LOGGER.info("Sent client's public key.");
        KeyPair dhKeyPair = KeysUtility.generateDHKeyPair();
        PublicKey clientDhPublicKey = dhKeyPair.getPublic();
        PrivateKey clientDhPrivateKey = dhKeyPair.getPrivate();
        out.writeObject(clientDhPublicKey);
        out.flush();
        PublicKey serverDhPublicKey = (PublicKey) in.readObject();
        LOGGER.info("Received server DH public key.");
        sessionKey = KeysUtility.generateSessionKey(clientDhPrivateKey, serverDhPublicKey);
        LOGGER.info("Key exchange complete.");
        LOGGER.info("Session Key (Client): " + EncryptionUtility.bytesToHex(sessionKey.getEncoded()));
    }

    // Getter functions
    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public PrivateKey getClientPrivateKey() {
        return clientPrivateKey;
    }

    public PublicKey getClientPublicKey() {
        return clientPublicKey;
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }
}