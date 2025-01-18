package Server;

import Utilities.DatabaseManager;
import Utilities.EncryptionUtility;
import Utilities.UserModel;
// import java.util.logging.Logger;

public class UserManager {
    //private static final Logger LOGGER = Logger.getLogger(UserManager.class.getName());

    public String registerUser(UserModel user) {
        UserModel sanitizedUser = sanitizeUser(user);
        String validationResult = validateUser(sanitizedUser);
        if ("Valid".equals(validationResult)) {
            boolean registrationSuccess = new DatabaseManager().registerUser(sanitizedUser);
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

    public UserModel loginUser(String email, String password) {
        return new DatabaseManager().loginUser(email, password);
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