package Server;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.crypto.*;

import Utilities.DatabaseManager;
import Utilities.EncryptionUtility;
import Utilities.KeysUtility;
import Utilities.UserModel;

public class ClientHandler {
    private final Socket clientSocket;
    private final Logger LOGGER = Logger.getLogger(ClientHandler.class.getName());
    private PublicKey serverPublicKey;
    private PublicKey clientPublicKey;
    private SecretKey sessionKey;

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
        UserModel sanitizedUser = sanitizeUser(user);
        String validationResult = validateUser(sanitizedUser);
        if ("Valid".equals(validationResult)) {
            boolean registrationSuccess = new DatabaseManager().registerUser(sanitizedUser);
            if (registrationSuccess) {
                UserModel loggedInUser = new DatabaseManager().loginUser(sanitizedUser.getEmail(),
                        sanitizedUser.getPassword());
                if (loggedInUser != null) {
                    out.writeObject(loggedInUser);
                    LOGGER.info("UserModel registered and automatically logged in: " + sanitizedUser.getEmail());
                } else {
                    out.writeObject("Login failed after registration. Please try to login manually.");
                }
            } else {
                out.writeObject("Registration failed. Please try again.");
            }
        } else {
            out.writeObject(validationResult);
        }
    }

    private void handleLogin(ObjectOutputStream out, ObjectInputStream in) throws IOException, ClassNotFoundException {
        String email = EncryptionUtility.sanitize((String) in.readObject());
        String password = EncryptionUtility.sanitize((String) in.readObject());
        out.writeObject(new DatabaseManager().loginUser(email, password));
    }

    private void handleReservation(ObjectOutputStream out, ObjectInputStream in) throws IOException,
            ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        byte[] encryptedData = (byte[]) in.readObject();
        byte[] signature = (byte[]) in.readObject();
        String reservationData = EncryptionUtility.decrypt(encryptedData, sessionKey);
        UserModel user = (UserModel) in.readObject();
        String userEmail = EncryptionUtility.sanitize(user.getEmail());
        if (EncryptionUtility.verifySignature(reservationData, signature, clientPublicKey)) {
            String[] parts = reservationData.split(", ");
            if (parts.length == 2
                    && new DatabaseManager().isSpotReserved(parts[0].split(": ")[1], parts[1].split(": ")[1])) {
                out.writeObject(EncryptionUtility.encrypt("Spot is already reserved.", sessionKey));
            } else {
                byte[] encryptedPaymentData = (byte[]) in.readObject();
                String paymentData = EncryptionUtility.decrypt(encryptedPaymentData, sessionKey);
                String[] paymentParts = paymentData.split(", ");
                boolean success = paymentParts.length == 2 &&
                        new DatabaseManager().processPayment(paymentParts[0].split(": ")[1],
                                paymentParts[1].split(": ")[1])
                        &&
                        new DatabaseManager().reserveSpot(userEmail, parts[0].split(": ")[1], parts[1].split(": ")[1]);
                out.writeObject(EncryptionUtility.encrypt(
                        success ? "Reservation and payment successful!" : "Failed to reserve spot or process payment.",
                        sessionKey));
                new DatabaseManager().logActivity(userEmail, reservationData, bytesToHex(signature));
            }
        } else {
            out.writeObject(EncryptionUtility.encrypt("Invalid signature.", sessionKey));
        }
    }

    private UserModel sanitizeUser(UserModel user) {
        return new UserModel(
                EncryptionUtility.sanitize(user.getFullName()),
                EncryptionUtility.sanitize(user.getUserType()),
                EncryptionUtility.sanitize(user.getPhoneNumber()),
                EncryptionUtility.sanitize(user.getCarPlate()),
                EncryptionUtility.sanitize(user.getEmail()),
                EncryptionUtility.sanitize(user.getPassword()));
    }

    private String validateUser(UserModel user) {
        // Validate email format
        if (!user.getEmail().matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
            return "Email is not in a valid format.";
        }
        // Validate car plate
        if (!user.getCarPlate().matches("\\d{7}")) {
            return "Car plate must be a 7-digit number.";
        }
        // Validate password length
        if (user.getPassword().length() < 10) {
            return "Password must be at least 10 characters long.";
        }
        // Validate phone number
        if (!user.getPhoneNumber().matches("09\\d{8}")) {
            return "Phone number must be 10 digits and start with 09.";
        }
        // Validate user type
        if (!(user.getUserType().equals("employee") || user.getUserType().equals("visitor"))) {
            return "UserModel type must be 'employee' or 'visitor'.";
        }
        // Check if email already exists
        if (new DatabaseManager().emailExists(user.getEmail())) {
            return "Email is already registered.";
        }
        return "Valid";
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void closeConnection() {
        try (clientSocket) {
            LOGGER.info("ClientHandler is closing resources.");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error closing client socket", e);
        }
    }
}