package Server.modules;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import Server.ParkingServer;
import Utilities.DatabaseManager;
import Utilities.EncryptionUtility;
import Utilities.UserModel;

public class UserManager {

    private static final Logger LOGGER = Logger.getLogger(ParkingServer.class.getName());

    // Helper method for hashing
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException | java.io.UnsupportedEncodingException e) {
            LOGGER.log(Level.SEVERE, "Hashing failed", e);
            return null;
        }
    }

    public String registerUser(UserModel user) {
        UserModel sanitizedUser = sanitizeUser(user);
        String validationResult = validateUser(sanitizedUser);
        if ("Valid".equals(validationResult)) {
            try {
                // Store the original password temporarily
                String originalPassword = sanitizedUser.getPassword();
                // Hash the password before storing
                String hashedPassword = hashPassword(originalPassword);
                if (hashedPassword == null) {
                    return "Registration failed due to an internal error.";
                }
                sanitizedUser.setPassword(hashedPassword);
                LOGGER.info("Original Password: " + originalPassword);
                LOGGER.info("Hashed Password Stored: " + hashedPassword);

                boolean registrationSuccess = new DatabaseManager().registerUser(sanitizedUser);
                if (registrationSuccess) {
                    // Use the original password for login attempt
                    UserModel loggedInUser = loginUser(sanitizedUser.getEmail(), originalPassword);
                    if (loggedInUser != null) {
                        return "Registration and login successful!";
                    } else {
                        return "Login failed after registration. Please try to login manually.";
                    }
                } else {
                    return "Registration failed. Please try again.";
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error during registration", e);
                return "Registration failed due to an internal error.";
            }
        } else {
            return validationResult;
        }
    }

    // Attempts login request to the DB
    public UserModel loginUser(String email, String providedPassword) {
        try {

            UserModel user = new DatabaseManager().getUserByEmail(email);
            if (user != null) {
                // Hash the provided password for comparison
                String hashedAttempt = hashPassword(providedPassword);
                LOGGER.info("Login Attempt Password: " + providedPassword);
                LOGGER.info("Hashed Login Attempt: " + hashedAttempt);
                LOGGER.info("Stored Password: " + user.getPassword());
                if (hashedAttempt.equals(user.getPassword())) {
                    return user;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during login attempt", e);
        }
        return null;
    }

    // Santizing the user before attempting to register to the DB
    // To protect from SQL injection and XSS attacks
    private UserModel sanitizeUser(UserModel user) {
        return new UserModel(
                EncryptionUtility.sanitize(user.getFullName()),
                EncryptionUtility.sanitize(user.getUserType()),
                EncryptionUtility.sanitize(user.getPhoneNumber()),
                EncryptionUtility.sanitize(user.getCarPlate()),
                EncryptionUtility.sanitize(user.getEmail()),
                EncryptionUtility.sanitize(user.getPassword()));
    }

    // Validating the user's information to match certain criterea
    private String validateUser(UserModel user) {
        if (!user.getEmail().matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
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
            return "UserModel type must be 'employee' or 'visitor'.";
        }
        if (new DatabaseManager().emailExists(user.getEmail())) {
            return "Email is already registered.";
        }
        return "Valid";
    }
}