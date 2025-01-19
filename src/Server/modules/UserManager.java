package Server.modules;

import Utilities.DatabaseManager;
import Utilities.EncryptionUtility;
import Utilities.UserModel;

public class UserManager {
    // Attempts the Registration process
    public String registerUser(UserModel user) {
        UserModel sanitizedUser = sanitizeUser(user);
        String validationResult = validateUser(sanitizedUser);
        // if the user is valid then the user is added to the DB
        if ("Valid".equals(validationResult)) {
            boolean registrationSuccess = new DatabaseManager().registerUser(sanitizedUser);
            // if the registration is successful the client automatically logs in
            if (registrationSuccess) {
                UserModel loggedInUser = loginUser(sanitizedUser.getEmail(), sanitizedUser.getPassword());
                if (loggedInUser != null) {
                    return "Registration and login successful!";
                } else {
                    return "Login failed after registration. Please try to login manually.";
                }
            } else {
                return "Registration failed. Please try again.";
            }
        } else {
            return validationResult;
        }
    }

    // Attempts login request to the DB
    public UserModel loginUser(String email, String password) {
        return new DatabaseManager().loginUser(email, password);
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