

import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;

import utilities.CertificateAuthority;
import utilities.EncryptionUtility;
import utilities.KeysUtility;

import java.util.logging.Level;

public class ParkingServer {
    private static final int PORT = 3000;
    private static final String DB_URL = "jdbc:mysql://localhost:3306/parking_system";
    private static final String DB_USER = "bravonovember";
    private static final String DB_PASSWORD = "password";
    private static final Logger LOGGER = Logger.getLogger(ParkingServer.class.getName());

    public static void main(String[] args) {
        CertificateAuthority ca = new CertificateAuthority(); // Initialize CA
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            LOGGER.info("Parking Server is running on port " + PORT);
            ExecutorService executor = Executors.newFixedThreadPool(10);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                executor.execute(new ClientHandler(clientSocket, ca));
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error starting server.", e);
        }
    }

    static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private KeyPair serverKeyPair;
        private PublicKey clientPublicKey;
        private SecretKey sessionKey;
        private final CertificateAuthority ca;

        public ClientHandler(Socket clientSocket, CertificateAuthority ca) {
            this.clientSocket = clientSocket;
            this.ca = ca;
        }

        @Override
        public void run() {
            try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                    ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {
                LOGGER.info("ClientHandler started.");
                performKeyExchange(out, in);

                boolean running = true;
                while (running) {
                    String requestType = (String) in.readObject();
                    switch (requestType) {
                        case "close":
                            running = false;
                            break;
                        case "register":
                            handleUserRegistration(out, in);
                            break;
                        case "login":
                            handleUserLogin(out, in);
                            break;
                        case "reserve":
                            handleReservation(out, in);
                            break;
                    }
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error processing client request.", e);
            }
        }

        private void performKeyExchange(ObjectOutputStream out, ObjectInputStream in)
                throws IOException, ClassNotFoundException, GeneralSecurityException {
            serverKeyPair = KeysUtility.generateRSAKeyPair();
            out.writeObject(serverKeyPair.getPublic());
            clientPublicKey = (PublicKey) in.readObject();

            KeyPair dhKeyPair = KeysUtility.generateDHKeyPair();
            out.writeObject(dhKeyPair.getPublic());

            PublicKey clientDhPublicKey = (PublicKey) in.readObject();
            sessionKey = KeysUtility.generateSessionKey(dhKeyPair.getPrivate(), clientDhPublicKey);
            LOGGER.info("Key exchange complete.");
        }

        private void handleUserRegistration(ObjectOutputStream out, ObjectInputStream in)
                throws IOException, ClassNotFoundException, SQLException {
            User user = (User) in.readObject();
            String validationResult = validateUser(user);
            if ("Valid".equals(validationResult)) {
                boolean isRegistered = registerUser(user);
                out.writeObject(isRegistered ? "Registration successful!" : "Registration failed. Please try again.");
            } else {
                out.writeObject(validationResult);
            }
        }

        private void handleUserLogin(ObjectOutputStream out, ObjectInputStream in)
                throws IOException, ClassNotFoundException, SQLException, GeneralSecurityException {
            String email = (String) in.readObject();
            String password = (String) in.readObject();

            String clientCertificate = (String) in.readObject();
            boolean isCertificateValid = ca.verifyCertificate(clientCertificate, clientPublicKey);

            LOGGER.info("Email: " + email);
            LOGGER.info("Password: " + password);
            LOGGER.info("Client's Certificate: " + clientCertificate);
            LOGGER.info(
                    "Encoded Client Public Key: " + Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()));
            LOGGER.info("Certificate Verification Result: " + isCertificateValid);

            if (!isCertificateValid) {
                out.writeObject("Certificate verification failed.");
                return;
            }

            User user = loginUser(email, password);
            out.writeObject(user != null ? user : "Login failed. Invalid email or password.");
        }

        private void handleReservation(ObjectOutputStream out, ObjectInputStream in)
                throws IOException, ClassNotFoundException, GeneralSecurityException, SQLException {
            byte[] encryptedData = (byte[]) in.readObject();
            byte[] signature = (byte[]) in.readObject();
            String reservationData = EncryptionUtility.decrypt(encryptedData, sessionKey);
            User user = (User) in.readObject();
            String clientCertificate = (String) in.readObject();

            boolean isCertificateValid = ca.verifyCertificate(clientCertificate, clientPublicKey);

            LOGGER.info("Reservation Data: " + reservationData);
            LOGGER.info("Client's Certificate: " + clientCertificate);
            LOGGER.info(
                    "Encoded Client Public Key: " + Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()));
            LOGGER.info("Certificate Verification Result: " + isCertificateValid);

            if (isCertificateValid) {
                if (EncryptionUtility.verifySignature(reservationData, signature, clientPublicKey)) {
                    processReservation(out, in, reservationData, user);
                } else {
                    out.writeObject(EncryptionUtility.encrypt("Invalid signature.", sessionKey));
                }
            } else {
                out.writeObject(EncryptionUtility.encrypt("Certificate verification failed.", sessionKey));
            }
        }

        private void processReservation(ObjectOutputStream out, ObjectInputStream in, String reservationData, User user)
                throws IOException, SQLException, GeneralSecurityException, ClassNotFoundException {
            byte[] signature = (byte[]) in.readObject();

            String[] parts = reservationData.split(", ");
            if (isSpotReserved(parts[0].split(": ")[1], parts[1].split(": ")[1])) {
                out.writeObject(EncryptionUtility.encrypt("Spot is already reserved.", sessionKey));
            } else {
                byte[] encryptedPaymentData = (byte[]) in.readObject();
                String paymentData = EncryptionUtility.decrypt(encryptedPaymentData, sessionKey);
                boolean success = isValidPaymentData(paymentData)
                        && reserveSpot(user.getEmail(), parts[0].split(": ")[1], parts[1].split(": ")[1])
                        && processPayment(paymentData);
                out.writeObject(EncryptionUtility.encrypt(
                        success ? "Reservation and payment successful!" : "Failed to reserve spot or process payment.",
                        sessionKey));
                logActivity(user.getEmail(), reservationData, bytesToHex(signature));
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
            if (!isValidEmail(user.getEmail())) {
                return "Email is not in a valid format.";
            }
            if (!user.getCarPlate().matches("\\d{7}")) {
                return "Car plate must be a 7-digit number.";
            }
            if (user.getPassword().length() < 10) {
                return "Password must be at least 10 characters long.";
            }
            if (!user.getPhoneNumber().matches("09\\d{8}")) {
                return "Phone number must be 10 digits and start with 09.";
            }
            if (!(user.getUserType().equals("employee") || user.getUserType().equals("visitor"))) {
                return "User type must be 'employee' or 'visitor'.";
            }
            return emailExists(user.getEmail()) ? "Email is already registered." : "Valid";
        }

        private boolean emailExists(String email) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE email = ?")) {
                stmt.setString(1, email);
                try (ResultSet rs = stmt.executeQuery()) {
                    return rs.next();
                }
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error checking email existence.", e);
                return false;
            }
        }

        private boolean registerUser(User user) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                 PreparedStatement stmt = conn.prepareStatement("INSERT INTO users (full_name, user_type, phone_number, car_plate, email, password) VALUES (?, ?, ?, ?, ?, ?)")) {
                stmt.setString(1, user.getFullName());
                stmt.setString(2, user.getUserType());
                stmt.setString(3, user.getPhoneNumber());
                stmt.setString(4, user.getCarPlate());
                stmt.setString(5, user.getEmail());
                stmt.setString(6, user.getPassword());
                stmt.executeUpdate();
                return true;
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error registering user.", e);
                return false;
            }
        }

        private User loginUser(String email, String password) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement stmt = conn
                            .prepareStatement("SELECT * FROM users WHERE email = ? AND password = ?")) {
                stmt.setString(1, email);
                stmt.setString(2, password);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return new User(
                                rs.getString("full_name"),
                                rs.getString("user_type"),
                                rs.getString("phone_number"),
                                rs.getString("car_plate"),
                                rs.getString("email"),
                                rs.getString("password"));
                    }
                }
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error logging in user.", e);
            }
            return null;
        }

        private boolean isSpotReserved(String parkingSpot, String time) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement stmt = conn.prepareStatement(
                            "SELECT * FROM reservations WHERE parking_spot = ? AND reservation_time = ?")) {
                stmt.setString(1, parkingSpot);
                stmt.setString(2, time);
                try (ResultSet rs = stmt.executeQuery()) {
                    return rs.next();
                }
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error checking reservation.", e);
                return false;
            }
        }

        private boolean reserveSpot(String userEmail, String parkingSpot, String time) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement stmt = conn.prepareStatement(
                            "INSERT INTO reservations (user_email, parking_spot, reservation_time) VALUES (?, ?, ?)")) {
                stmt.setString(1, userEmail);
                stmt.setString(2, parkingSpot);
                stmt.setString(3, time);
                stmt.executeUpdate();
                return true;
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error reserving parking spot.", e);
                return false;
            }
        }

        private boolean processPayment(String paymentData) {
            String[] paymentParts = extractPaymentData(paymentData);
            return paymentParts != null && savePaymentDetails(paymentParts[0], paymentParts[1]);
        }

        private String[] extractPaymentData(String paymentData) {
            String[] paymentParts = paymentData.split(", ");
            if (paymentParts.length == 2) {
                String creditCardNumber = paymentParts[0].split(": ")[1];
                String pin = paymentParts[1].split(": ")[1];
                return new String[] { creditCardNumber, pin };
            }
            return null;
        }

        private boolean savePaymentDetails(String creditCardNumber, String pin) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement stmt = conn
                            .prepareStatement("INSERT INTO payments (credit_card_number, pin) VALUES (?, ?)")) {
                stmt.setString(1, creditCardNumber);
                stmt.setString(2, pin);
                stmt.executeUpdate();
                return true;
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error processing payment.", e);
                return false;
            }
        }

        private boolean isValidPaymentData(String paymentData) {
            String[] paymentParts = extractPaymentData(paymentData);
            return paymentParts != null && isValidCreditCard(paymentParts[0]) && isValidPin(paymentParts[1]);
        }

        private boolean isValidCreditCard(String creditCardNumber) {
            return creditCardNumber.matches("\\d{16}");
        }

        private boolean isValidPin(String pin) {
            return pin.matches("\\d{4}");
        }

        private boolean isValidEmail(String email) {
            return Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$").matcher(email).matches();
        }

        private void logActivity(String userEmail, String requestData, String signature) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement stmt = conn.prepareStatement(
                            "INSERT INTO activity_log (user_email, request_data, signature) VALUES (?, ?, ?)")) {
                stmt.setString(1, userEmail);
                stmt.setString(2, requestData);
                stmt.setString(3, signature);
                stmt.executeUpdate();
                LOGGER.info("Activity logged successfully.");
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error logging activity.", e);
            }
        }
    }
}
