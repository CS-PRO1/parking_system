import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.crypto.*;

public class ParkingServer {
    private static final int PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingServer.class.getName());

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            LOGGER.info("Parking Server is running on port " + PORT);
            ExecutorService executor = Executors.newFixedThreadPool(10);

            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    executor.execute(new ClientHandler(clientSocket));
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error accepting client connection.", e);
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error starting server.", e);
        }
    }

    static class ClientHandler implements Runnable {
        final private Socket clientSocket;
        private KeyPair serverKeyPair;
        private PublicKey clientPublicKey;
        private SecretKey sessionKey;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                    ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {
                LOGGER.info("ClientHandler started.");
                serverKeyPair = KeysUtility.generateRSAKeyPair();
                PublicKey serverPublicKey = serverKeyPair.getPublic();
                // PrivateKey serverPrivateKey = serverKeyPair.getPrivate(); // Not used here
                out.writeObject(serverPublicKey);
                clientPublicKey = (PublicKey) in.readObject();
                LOGGER.info("Received client's public key.");
                PublicKey clientDhPublicKey = (PublicKey) in.readObject();
                KeyPair dhKeyPair = KeysUtility.generateDHKeyPair();
                PublicKey serverDhPublicKey = dhKeyPair.getPublic();
                PrivateKey serverDhPrivateKey = dhKeyPair.getPrivate();
                out.writeObject(serverDhPublicKey);
                sessionKey = KeysUtility.generateSessionKey(serverDhPrivateKey, clientDhPublicKey);
                LOGGER.info("Key exchange complete.");
                boolean running = true;
                while (running) {
                    String requestType = (String) in.readObject();
                    if (requestType.equals("close")) {
                        running = false;
                    } else if ("register".equals(requestType)) {
                        User user = (User) in.readObject();
                        String validationResult = validateUser(user);
                        out.writeObject(
                                validationResult.equals("Valid")
                                        ? new DatabaseManager().registerUser(user) ? "Registration successful!"
                                                : "Registration failed. Please try again."
                                        : validationResult);
                    } else if ("login".equals(requestType)) {
                        out.writeObject(
                                new DatabaseManager().loginUser((String) in.readObject(), (String) in.readObject()));
                    } else if ("reserve".equals(requestType)) {
                        byte[] encryptedData = (byte[]) in.readObject();
                        byte[] signature = (byte[]) in.readObject();
                        String reservationData = EncryptionUtility.decrypt(encryptedData, sessionKey);
                        User user = (User) in.readObject();
                        String userEmail = user.getEmail();
                        if (EncryptionUtility.verifySignature(reservationData, signature, clientPublicKey)) {
                            String[] parts = reservationData.split(", ");
                            if (parts.length == 2 && new DatabaseManager().isSpotReserved(parts[0].split(": ")[1],
                                    parts[1].split(": ")[1])) {
                                out.writeObject(EncryptionUtility.encrypt("Spot is already reserved.", sessionKey));
                            } else {
                                byte[] encryptedPaymentData = (byte[]) in.readObject();
                                String paymentData = EncryptionUtility.decrypt(encryptedPaymentData, sessionKey);
                                String[] paymentParts = paymentData.split(", ");
                                boolean success = paymentParts.length == 2 &&
                                        new DatabaseManager().processPayment(paymentParts[0].split(": ")[1],
                                                paymentParts[1].split(": ")[1])
                                        &&
                                        new DatabaseManager().reserveSpot(userEmail, parts[0].split(": ")[1],
                                                parts[1].split(": ")[1]);
                                out.writeObject(
                                        EncryptionUtility.encrypt(success ? "Reservation and payment successful!"
                                                : "Failed to reserve spot or process payment.", sessionKey));
                                new DatabaseManager().logActivity(userEmail, reservationData, bytesToHex(signature));
                            }
                        } else {
                            out.writeObject(EncryptionUtility.encrypt("Invalid signature.", sessionKey));
                        }
                    }
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error processing client request.", e);
            } finally {
                try (clientSocket) {
                    LOGGER.info("ClientHandler is closing resources.");
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "client socket error", e);
                }
            }
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        private String validateUser(User user) {
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
                return "User type must be 'employee' or 'visitor'.";
            }
            // Check if email already exists
            if (new DatabaseManager().emailExists(user.getEmail())) {
                return "Email is already registered.";
            }
            return "Valid";
        }
    }
}