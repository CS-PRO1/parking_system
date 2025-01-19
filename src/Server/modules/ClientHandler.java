package Server.modules;

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

    // Method to initialize the I/O streams and key handshake and begin receiving
    // requests and finally shutting down the connection.
    public void initializeHandler() {
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

    // Generates the RSA keys and completes the key handshake
    private void initializeKeyExchange(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {
        KeyPair serverKeyPair = KeysUtility.generateRSAKeyPair();
        serverPublicKey = serverKeyPair.getPublic();
        out.writeObject(serverPublicKey);
        clientPublicKey = (PublicKey) in.readObject();
        LOGGER.info("Received client's public key.");
        // receives the client's DH public key to generate a session key
        PublicKey clientDhPublicKey = (PublicKey) in.readObject();
        KeyPair dhKeyPair = KeysUtility.generateDHKeyPair();
        out.writeObject(dhKeyPair.getPublic());
        sessionKey = KeysUtility.generateSessionKey(dhKeyPair.getPrivate(), clientDhPublicKey);
        LOGGER.info("Key exchange complete.");
    }

    // recieve's the client's message and routes the request to the respective
    // method to handle it
    private void processClientRequests(ObjectOutputStream out, ObjectInputStream in) {
        boolean running = true;
        try {
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
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error Processing Client request", e);
        }
    }

    // Handles the Registration request
    private void handleRegistration(ObjectOutputStream out, ObjectInputStream in) {
        try {
            UserModel user = (UserModel) in.readObject();
            String result = userManager.registerUser(user);
            if (result.startsWith("Registration and login successful!")) {
                UserModel loggedInUser = userManager.loginUser(user.getEmail(), user.getPassword());
                out.writeObject(loggedInUser);
            } else {
                out.writeObject(result);
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error Processing Registration Request", e);
        }
    }

    // Handles the Login Request
    private void handleLogin(ObjectOutputStream out, ObjectInputStream in) {
        try {
            String email = EncryptionUtility.sanitize((String) in.readObject());
            String password = EncryptionUtility.sanitize((String) in.readObject());
            out.writeObject(userManager.loginUser(email, password));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error Processing Login Request", e);
        }
    }

    // Handles the Reservation request
    private void handleReservation(ObjectOutputStream out, ObjectInputStream in) {
        try {
            byte[] encryptedData = (byte[]) in.readObject();
            byte[] signature = (byte[]) in.readObject();
            String reservationData = EncryptionUtility.decrypt(encryptedData, sessionKey);
            UserModel user = (UserModel) in.readObject();
            byte[] encryptedPaymentData = (byte[]) in.readObject();
            String paymentData = EncryptionUtility.decrypt(encryptedPaymentData, sessionKey);

            byte[] response = reservationManager.handleReservation(reservationData, paymentData, user, sessionKey,
                    clientPublicKey, signature);
            out.writeObject(response);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error Processing Reservation Request", e);
        }
    }

    // Closes the network connection
    private void closeConnection() {
        try (clientSocket) {
            LOGGER.info("ClientHandler is closing resources.");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error closing client socket", e);
        }
    }
}