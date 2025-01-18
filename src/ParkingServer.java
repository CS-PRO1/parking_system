import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.logging.Level;
import javax.crypto.*;


public class ParkingServer {
    private static final int PORT = 3000;
    private static final String DB_URL = "jdbc:mysql://localhost:3306/parking_system";
    private static final String DB_USER = "bravonovember";
    private static final String DB_PASSWORD = "password";
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
                PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
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
                                        ? registerUser(user) ? "Registration successful!"
                                                : "Registration failed. Please try again."
                                        : validationResult);
                    } else if ("login".equals(requestType)) {
                        out.writeObject(loginUser((String) in.readObject(), (String) in.readObject()));
                    } else if ("reserve".equals(requestType)) {
                        byte[] encryptedData = (byte[]) in.readObject();
                        byte[] signature = (byte[]) in.readObject();
                        String reservationData = EncryptionUtility.decrypt(encryptedData, sessionKey);
                        User user = (User) in.readObject();
                        String userEmail = user.getEmail();
                        if (EncryptionUtility.verifySignature(reservationData, signature, clientPublicKey)) {
                            String[] parts = reservationData.split(", ");
                            if (parts.length == 2 && isSpotReserved(parts[0].split(": ")[1], parts[1].split(": ")[1])) {
                                out.writeObject(EncryptionUtility.encrypt("Spot is already reserved.", sessionKey));
                            } else {
                                byte[] encryptedPaymentData = (byte[]) in.readObject();
                                boolean success = isValidPaymentData(
                                        EncryptionUtility.decrypt(encryptedPaymentData, sessionKey))
                                        && reserveSpot(userEmail, parts[0].split(": ")[1], parts[1].split(": ")[1])
                                        && processPayment(EncryptionUtility.decrypt(encryptedPaymentData, sessionKey));
                                out.writeObject(
                                        EncryptionUtility.encrypt(success ? "Reservation and payment successful!"
                                                : "Failed to reserve spot or process payment.", sessionKey));
                                logActivity(userEmail, reservationData, bytesToHex(signature));
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
            if (!isValidEmail(user.getEmail())) {
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
            if (emailExists(user.getEmail())) {
                return "Email is already registered.";
            }
            return "Valid";
        }

        private boolean registerUser(User user) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "INSERT INTO users (full_name, user_type, phone_number, car_plate, email, password) VALUES (?, ?, ?, ?, ?, ?)";
                PreparedStatement stmt = conn.prepareStatement(query);
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
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "SELECT * FROM users WHERE email = ? AND password = ?";
                PreparedStatement stmt = conn.prepareStatement(query);
                stmt.setString(1, email);
                stmt.setString(2, password);
                ResultSet rs = stmt.executeQuery();

                if (rs.next()) {
                    return new User(
                            rs.getString("full_name"),
                            rs.getString("user_type"),
                            rs.getString("phone_number"),
                            rs.getString("car_plate"),
                            rs.getString("email"),
                            rs.getString("password"));
                }
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error logging in user.", e);
            }
            return null;
        }

        private boolean isValidEmail(String email) {
            String emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
            Pattern pattern = Pattern.compile(emailRegex);
            return pattern.matcher(email).matches();
        }

        private boolean emailExists(String email) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "SELECT * FROM users WHERE email = ?";
                PreparedStatement stmt = conn.prepareStatement(query);
                stmt.setString(1, email);
                ResultSet rs = stmt.executeQuery();
                return rs.next();
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error checking email existence.", e);
            }
            return false;
        }

        private boolean isSpotReserved(String parkingSpot, String time) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "SELECT * FROM reservations WHERE parking_spot = ? AND reservation_time = ?";
                PreparedStatement stmt = conn.prepareStatement(query);
                stmt.setString(1, parkingSpot);
                stmt.setString(2, time);
                ResultSet rs = stmt.executeQuery();
                LOGGER.info("Checked spot reservation status: " + rs.next());
                return rs.next();
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error checking reservation.", e);
            }
            return false;
        }

        private boolean reserveSpot(String userEmail, String parkingSpot, String time) {
            LOGGER.info("Entered reserveSpot function."); // Log statement at the start
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "INSERT INTO reservations (user_email, parking_spot, reservation_time) VALUES (?, ?, ?)";
                PreparedStatement stmt = conn.prepareStatement(query);
                stmt.setString(1, userEmail);
                stmt.setString(2, parkingSpot);
                stmt.setString(3, time);
                LOGGER.info("Executing query: " + stmt); // Log statement before executing query
                stmt.executeUpdate();
                LOGGER.info("Reservation successfully inserted.");
                return true;
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error reserving parking spot.", e);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Unexpected error.", e);
            }
            return false;
        }

        private boolean processPayment(String paymentData) {
            // Simulate payment processing logic
            LOGGER.info("Processing payment: " + paymentData);
            // Extract credit card number and PIN for validation
            String[] paymentParts = paymentData.split(", ");
            if (paymentParts.length == 2) {
                String creditCardNumber = paymentParts[0].split(": ")[1];
                String pin = paymentParts[1].split(": ")[1];

                if (isValidCreditCard(creditCardNumber) && isValidPin(pin)) {
                    // Store payment details in the database
                    try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                        String query = "INSERT INTO payments (credit_card_number, pin) VALUES (?, ?)";
                        PreparedStatement stmt = conn.prepareStatement(query);
                        stmt.setString(1, creditCardNumber);
                        stmt.setString(2, pin);
                        stmt.executeUpdate();
                        return true;
                    } catch (SQLException e) {
                        LOGGER.log(Level.SEVERE, "Error processing payment.", e);
                    }
                }
            }
            return false;
        }

        private boolean isValidPaymentData(String paymentData) {
            // Ensure payment data contains credit card number and PIN
            String[] paymentParts = paymentData.split(", ");
            if (paymentParts.length == 2) {
                String creditCardNumber = paymentParts[0].split(": ")[1];
                String pin = paymentParts[1].split(": ")[1];
                return isValidCreditCard(creditCardNumber) && isValidPin(pin);
            }
            return false;
        }

        private boolean isValidCreditCard(String creditCardNumber) {
            // Validate 16-digit credit card number
            return creditCardNumber.matches("\\d{16}");
        }

        private boolean isValidPin(String pin) {
            // Validate 4-digit PIN
            return pin.matches("\\d{4}");
        }

        private void logActivity(String userEmail, String requestData, String signature) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "INSERT INTO activity_log (user_email, request_data, signature) VALUES (?, ?, ?)";
                PreparedStatement stmt = conn.prepareStatement(query);
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