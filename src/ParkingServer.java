import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ParkingServer {
    private static final int PORT = 3000;
    private static final String DB_URL = "jdbc:mysql://localhost:3306/parking_system";
    private static final String DB_USER = "bravonovember";
    private static final String DB_PASSWORD = "password";
    private static final Logger LOGGER = Logger.getLogger(ParkingServer.class.getName());

    public static void main(String[] args) {
        try {
            // Load MySQL JDBC driver
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "MySQL JDBC Driver not found.", e);
            return;
        }

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
        private Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            ObjectOutputStream out = null;
            ObjectInputStream in = null;
            try {
                LOGGER.info("ClientHandler started.");
                out = new ObjectOutputStream(clientSocket.getOutputStream());
                in = new ObjectInputStream(clientSocket.getInputStream());

                // Key exchange
                LOGGER.info("Starting key exchange...");
                PublicKey clientPublicKey = (PublicKey) in.readObject();
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
                keyPairGen.initialize(2048);
                KeyPair keyPair = keyPairGen.generateKeyPair();
                PublicKey serverPublicKey = keyPair.getPublic();
                PrivateKey serverPrivateKey = keyPair.getPrivate();

                out.writeObject(serverPublicKey);
                LOGGER.info("Sent server public key.");

                KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
                keyAgree.init(serverPrivateKey);
                keyAgree.doPhase(clientPublicKey, true);
                byte[] sharedSecret = keyAgree.generateSecret();
                SecretKeySpec sessionKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                LOGGER.info("Key exchange complete.");
                LOGGER.info("Session Key (Server): " + bytesToHex(sessionKey.getEncoded()));

                boolean running = true;
                while (running) {
                    // Read user request type
                    String requestType = (String) in.readObject();
                    LOGGER.info("Received request type: " + requestType);
                    if (requestType.equals("close")) {
                        running = false;
                        LOGGER.info("Client requested to close the connection.");
                    } else if ("register".equals(requestType)) {
                        User user = (User) in.readObject();
                        String validationResult = validateUser(user);
                        if (validationResult.equals("Valid")) {
                            if (registerUser(user)) {
                                out.writeObject("Registration successful!");
                            } else {
                                out.writeObject("Registration failed. Please try again.");
                            }
                        } else {
                            out.writeObject("Registration failed: " + validationResult);
                        }
                    } else if ("login".equals(requestType)) {
                        String email = (String) in.readObject();
                        String password = (String) in.readObject();
                        User user = loginUser(email, password);
                        if (user != null) {
                            out.writeObject(user);
                        } else {
                            out.writeObject("Login failed. Invalid email or password.");
                        }
                    }
                    else if ("reserve".equals(requestType)) {
    // Receive and decrypt reservation data
    byte[] iv = (byte[]) in.readObject(); // Receive IV
    byte[] encryptedData = (byte[]) in.readObject();
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
    byte[] decryptedData = cipher.doFinal(encryptedData);
    String reservationData = new String(decryptedData);
    LOGGER.info("Received reservation data: " + reservationData);

    // Receive User object
    User user = (User) in.readObject();
    String userEmail = user.getEmail();
    LOGGER.info("Received User object with email: " + userEmail);

    // Parse reservation data
    String[] parts = reservationData.split(", ");
    if (parts.length == 2) {
        String parkingSpot = parts[0].split(": ")[1];
        String time = parts[1].split(": ")[1];

        LOGGER.info("Parking Spot: " + parkingSpot + ", Time: " + time + ", User Email: " + userEmail);

        // Check if spot is reserved
        if (isSpotReserved(parkingSpot, time)) {
            String response = "Spot is already reserved.";
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
            byte[] encryptedResponse = cipher.doFinal(response.getBytes());
            out.writeObject(encryptedResponse);
        } else {
            LOGGER.info("Calling reserveSpot function.");
            // Reserve spot
            boolean result = reserveSpot(userEmail, parkingSpot, time);
            if (result) {
                String response = "Reservation confirmed!";
                cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
                byte[] encryptedResponse = cipher.doFinal(response.getBytes());
                out.writeObject(encryptedResponse);
            } else {
                String response = "Failed to reserve spot.";
                cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
                byte[] encryptedResponse = cipher.doFinal(response.getBytes());
                out.writeObject(encryptedResponse);
            }
        }
    } else {
        LOGGER.warning("Reservation data format is incorrect.");
        String response = "Invalid reservation data format.";
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
        byte[] encryptedResponse = cipher.doFinal(response.getBytes());
        out.writeObject(encryptedResponse);
    }
}


                }

            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error processing client request.", e);
            } finally {
                try {
                    if (out != null)
                        out.close();
                    if (in != null)
                        in.close();
                    if (clientSocket != null)
                        clientSocket.close();
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error closing resources.", e);
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
            LOGGER.info("Entered reserveSpot function.");
            if (userEmail == null || userEmail.isEmpty() || parkingSpot == null || parkingSpot.isEmpty() || time == null
                    || time.isEmpty()) {
                LOGGER.warning("Invalid input data for reservation.");
                return false;
            }
            Connection conn = null;
            PreparedStatement stmt = null;
            try {
                LOGGER.info("Establishing database connection...");
                conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                LOGGER.info("Database connection established.");

                String query = "INSERT INTO reservations (user_email, parking_spot, reservation_time) VALUES (?, ?, ?)";
                stmt = conn.prepareStatement(query);
                stmt.setString(1, userEmail);
                stmt.setString(2, parkingSpot);
                stmt.setString(3, time);

                LOGGER.info("Prepared statement: " + stmt);
                int rowsAffected = stmt.executeUpdate();
                LOGGER.info("Rows affected: " + rowsAffected);
                LOGGER.info("Reservation successfully inserted.");
                return true;
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "SQL Error: " + e.getErrorCode() + " - " + e.getSQLState(), e);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Unexpected error.", e);
            } finally {
                try {
                    if (stmt != null) {
                        stmt.close();
                        LOGGER.info("Statement closed.");
                    }
                    if (conn != null) {
                        conn.close();
                        LOGGER.info("Connection closed.");
                    }
                } catch (SQLException e) {
                    LOGGER.log(Level.SEVERE, "Error closing resources.", e);
                }
            }
            return false;
        }

    }
}
