package Server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.crypto.*;

import Utilities.EncryptionUtility;
import Utilities.KeysUtility;
import Utilities.UserModel;

public class ClientHandler {
    private final Socket clientSocket;
    private final Logger LOGGER = Logger.getLogger(ClientHandler.class.getName());
    private PublicKey serverPublicKey;
    private PublicKey clientPublicKey;
    private SecretKey sessionKey;
    private UserManager userManager = new UserManager();
    private ReservationManager reservationManager = new ReservationManager();

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    public void handle() {
        try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {
            LOGGER.info("ClientHandler started.");
            initializeKeyExchange(out, in);
            processClientRequests(out, in);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error handling client operations.", e);
        } finally {
            closeConnection();
        }
    }

    private void initializeKeyExchange(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {
        KeyPair serverKeyPair = KeysUtility.generateRSAKeyPair();
        serverPublicKey = serverKeyPair.getPublic();
        out.writeObject(serverPublicKey);
        clientPublicKey = (PublicKey) in.readObject();
        LOGGER.info("Received client's public key.");

        PublicKey clientDhPublicKey = (PublicKey) in.readObject();
        KeyPair dhKeyPair = KeysUtility.generateDHKeyPair();
        out.writeObject(dhKeyPair.getPublic());
        sessionKey = KeysUtility.generateSessionKey(dhKeyPair.getPrivate(), clientDhPublicKey);
        LOGGER.info("Key exchange complete.");
    }

    private void processClientRequests(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        boolean running = true;
        while (running) {
            String requestType = (String) in.readObject();
            switch (requestType) {
                case "close":
                    running = false;
                    break;
                case "register":
                    handleRegistration(out, in);
                    break;
                case "login":
                    handleLogin(out, in);
                    break;
                case "reserve":
                    handleReservation(out, in);
                    break;
                default:
                    LOGGER.warning("Unknown request type: " + requestType);
            }
        }
    }

    private void handleRegistration(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        UserModel user = (UserModel) in.readObject();
        String result = userManager.registerUser(user);
        if (result.startsWith("Registration and login successful!")) {
            UserModel loggedInUser = userManager.loginUser(user.getEmail(), user.getPassword());
            out.writeObject(loggedInUser);
        } else {
            out.writeObject(result);
        }
    }

    private void handleLogin(ObjectOutputStream out, ObjectInputStream in) throws IOException, ClassNotFoundException {
        String email = EncryptionUtility.sanitize((String) in.readObject());
        String password = EncryptionUtility.sanitize((String) in.readObject());
        out.writeObject(userManager.loginUser(email, password));
    }

    private void handleReservation(ObjectOutputStream out, ObjectInputStream in) throws IOException,
            ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        byte[] encryptedData = (byte[]) in.readObject();
        byte[] signature = (byte[]) in.readObject();
        String reservationData = EncryptionUtility.decrypt(encryptedData, sessionKey);
        UserModel user = (UserModel) in.readObject();
        byte[] encryptedPaymentData = (byte[]) in.readObject();
        String paymentData = EncryptionUtility.decrypt(encryptedPaymentData, sessionKey);

        byte[] response = reservationManager.handleReservation(reservationData, paymentData, user, sessionKey,
                clientPublicKey, signature);
        out.writeObject(response);
    }

    private void closeConnection() {
        try (clientSocket) {
            LOGGER.info("ClientHandler is closing resources.");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error closing client socket", e);
        }
    }
}