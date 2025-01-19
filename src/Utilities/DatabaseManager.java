package Utilities;

import java.sql.*;
import java.util.logging.Logger;
import java.util.logging.Level;

public class DatabaseManager {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/parking_system";
    private static final String DB_USER = "bravonovember";
    private static final String DB_PASSWORD = "password";
    private static final Logger LOGGER = Logger.getLogger(DatabaseManager.class.getName());

    // Adds the user to the DB upon registeration
    public boolean registerUser(UserModel user) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "INSERT INTO users (full_name, user_type, phone_number, car_plate, email, password) VALUES (?, ?, ?, ?, ?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, user.getFullName());
                stmt.setString(2, user.getUserType());
                stmt.setString(3, user.getPhoneNumber());
                stmt.setString(4, user.getCarPlate());
                stmt.setString(5, user.getEmail());
                stmt.setString(6, user.getPassword());
                stmt.executeUpdate();
                return true;
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error registering user.", e);
            return false;
        }
    }

    // requests login info from the DB
    public UserModel loginUser(String email, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM users WHERE email = ? AND password = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, email);
                stmt.setString(2, password);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return new UserModel(
                                rs.getString("full_name"),
                                rs.getString("user_type"),
                                rs.getString("phone_number"),
                                rs.getString("car_plate"),
                                rs.getString("email"),
                                rs.getString("password"));
                    }
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error logging in user.", e);
        }
        return null;
    }

    // Checks if an email is already used by a previous user
    public boolean emailExists(String email) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM users WHERE email = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, email);
                try (ResultSet rs = stmt.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error checking email existence.", e);
        }
        return false;
    }

    // Checks if the spot the client tries to reserve has been already reserved
    public boolean isSpotReserved(String parkingSpot, String time) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM reservations WHERE parking_spot = ? AND reservation_time = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, parkingSpot);
                stmt.setString(2, time);
                try (ResultSet rs = stmt.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error checking reservation.", e);
        }
        return false;
    }

    // Reserving the Spot and adding the info to the DB
    public boolean reserveSpot(String userEmail, String parkingSpot, String time) {
        LOGGER.info("Entered reserveSpot function.");
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "INSERT INTO reservations (user_email, parking_spot, reservation_time) VALUES (?, ?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, userEmail);
                stmt.setString(2, parkingSpot);
                stmt.setString(3, time);
                LOGGER.info("Executing query: " + stmt);
                stmt.executeUpdate();
                LOGGER.info("Reservation successfully inserted.");
                return true;
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error reserving parking spot.", e);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Unexpected error in reserveSpot.", e);
        }
        return false;
    }

    // Processes user payment info to the DB
    public boolean processPayment(String creditCardNumber, String pin) {
        LOGGER.info("Processing payment with card: " + creditCardNumber + " and PIN: " + pin);
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "INSERT INTO payments (credit_card_number, pin) VALUES (?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, creditCardNumber);
                stmt.setString(2, pin);
                stmt.executeUpdate();
                return true;
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error processing payment.", e);
        }
        return false;
    }

    // logs all clients activity in a table in the DB
    public void logActivity(String userEmail, String requestData, String signature) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "INSERT INTO activity_log (user_email, request_data, signature) VALUES (?, ?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, userEmail);
                stmt.setString(2, requestData);
                stmt.setString(3, signature);
                stmt.executeUpdate();
                LOGGER.info("Activity logged successfully.");
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error logging activity.", e);
        }
    }
}