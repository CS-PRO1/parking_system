// import java.io.*;
// import java.net.*;
// import java.sql.*;
// import java.util.concurrent.Executors;
// import java.util.concurrent.ExecutorService;
// import java.util.regex.Pattern;

// public class ParkingServer {
//     private static final int PORT = 3000;
//     private static final String DB_URL = "jdbc:mysql://localhost:3306/parking_system";
//     private static final String DB_USER = "bravonovember";
//     private static final String DB_PASSWORD = "password";

//     public static void main(String[] args) {
//         try {
//             // Load MySQL JDBC driver
//             Class.forName("com.mysql.cj.jdbc.Driver");
//         } catch (ClassNotFoundException e) {
//             System.out.println("MySQL JDBC Driver not found.");
//             e.printStackTrace();
//             return;
//         }

//         try (ServerSocket serverSocket = new ServerSocket(PORT)) {
//             System.out.println("Parking Server is running on port " + PORT);
//             ExecutorService executor = Executors.newFixedThreadPool(10);

//             while (true) {
//                 Socket clientSocket = serverSocket.accept();
//                 executor.execute(new ClientHandler(clientSocket));
//             }
//         } catch (IOException e) {
//             e.printStackTrace();
//         }
//     }

//     static class ClientHandler implements Runnable {
//         private Socket clientSocket;

//         public ClientHandler(Socket clientSocket) {
//             this.clientSocket = clientSocket;
//         }

//         @Override
//         public void run() {
//             try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
//                     ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {

//                 // Read user request type
//                 String requestType = (String) in.readObject();

//                 if ("register".equals(requestType)) {
//                     User user = (User) in.readObject();
//                     String validationResult = validateUser(user);
//                     if (validationResult.equals("Valid")) {
//                         if (registerUser(user)) {
//                             out.writeObject("Registration successful!");
//                         } else {
//                             out.writeObject("Registration failed. Please try again.");
//                         }
//                     } else {
//                         out.writeObject("Registration failed: " + validationResult);
//                     }
//                 } else if ("login".equals(requestType)) {
//                     String email = (String) in.readObject();
//                     String password = (String) in.readObject();
//                     User user = loginUser(email, password);
//                     if (user != null) {
//                         out.writeObject(user);
//                     } else {
//                         out.writeObject("Login failed. Invalid email or password.");
//                     }
//                 }

//             } catch (IOException | ClassNotFoundException e) {
//                 e.printStackTrace();
//             } finally {
//                 try {
//                     clientSocket.close();
//                 } catch (IOException e) {
//                     e.printStackTrace();
//                 }
//             }
//         }

//         private String validateUser(User user) {
//             // Validate email format
//             if (!isValidEmail(user.getEmail())) {
//                 return "Email is not in a valid format.";
//             }
//             // Validate car plate
//             if (!user.getCarPlate().matches("\\d{7}")) {
//                 return "Car plate must be a 7-digit number.";
//             }
//             // Validate password length
//             if (user.getPassword().length() < 10) {
//                 return "Password must be at least 10 characters long.";
//             }
//             // Validate phone number
//             if (!user.getPhoneNumber().matches("09\\d{8}")) {
//                 return "Phone number must be 10 digits and start with 09.";
//             }
//             // Validate user type
//             if (!(user.getUserType().equals("employee") || user.getUserType().equals("visitor"))) {
//                 return "User type must be 'employee' or 'visitor'.";
//             }
//             // Check if email already exists
//             if (emailExists(user.getEmail())) {
//                 return "Email is already registered.";
//             }
//             return "Valid";
//         }

//         private boolean registerUser(User user) {
//             try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
//                 String query = "INSERT INTO users (full_name, user_type, phone_number, car_plate, email, password) VALUES (?, ?, ?, ?, ?, ?)";
//                 PreparedStatement stmt = conn.prepareStatement(query);
//                 stmt.setString(1, user.getFullName());
//                 stmt.setString(2, user.getUserType());
//                 stmt.setString(3, user.getPhoneNumber());
//                 stmt.setString(4, user.getCarPlate());
//                 stmt.setString(5, user.getEmail());
//                 stmt.setString(6, user.getPassword());
//                 stmt.executeUpdate();
//                 return true;
//             } catch (SQLException e) {
//                 e.printStackTrace();
//                 return false;
//             }
//         }

//         private User loginUser(String email, String password) {
//             try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
//                 String query = "SELECT * FROM users WHERE email = ? AND password = ?";
//                 PreparedStatement stmt = conn.prepareStatement(query);
//                 stmt.setString(1, email);
//                 stmt.setString(2, password);
//                 ResultSet rs = stmt.executeQuery();

//                 if (rs.next()) {
//                     return new User(
//                             rs.getString("full_name"),
//                             rs.getString("user_type"),
//                             rs.getString("phone_number"),
//                             rs.getString("car_plate"),
//                             rs.getString("email"),
//                             rs.getString("password"));
//                 }
//             } catch (SQLException e) {
//                 e.printStackTrace();
//             }
//             return null;
//         }

//         private boolean isValidEmail(String email) {
//             String emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
//             Pattern pattern = Pattern.compile(emailRegex);
//             return pattern.matcher(email).matches();
//         }

//         private boolean emailExists(String email) {
//             try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
//                 String query = "SELECT * FROM users WHERE email = ?";
//                 PreparedStatement stmt = conn.prepareStatement(query);
//                 stmt.setString(1, email);
//                 ResultSet rs = stmt.executeQuery();
//                 return rs.next();
//             } catch (SQLException e) {
//                 e.printStackTrace();
//             }
//             return false;
//         }
//     }
// }

import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.crypto.*;
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
                    } else if ("reserve".equals(requestType)) {
                        byte[] encryptedData = (byte[]) in.readObject();
                        Cipher cipher = Cipher.getInstance("AES");
                        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
                        byte[] decryptedData = cipher.doFinal(encryptedData);
                        String reservationData = new String(decryptedData);

                        // Process reservation
                        LOGGER.info("Reservation Data: " + reservationData);

                        // Confirm reservation
                        String response = "Reservation confirmed!";
                        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                        byte[] encryptedResponse = cipher.doFinal(response.getBytes());
                        out.writeObject(encryptedResponse);
                    }
                }

            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException
                    | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
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
    }
}
