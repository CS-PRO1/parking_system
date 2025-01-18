package Utilities;
import java.io.Serializable;

public class UserModel implements Serializable {
    private String fullName;
    private String userType;
    private String phoneNumber;
    private String carPlate;
    private String email;
    private String password;

    public UserModel(String fullName, String userType, String phoneNumber, String carPlate, String email, String password) {
        this.fullName = fullName;
        this.userType = userType;
        this.phoneNumber = phoneNumber;
        this.carPlate = carPlate;
        this.email = email;
        this.password = password;
    }

    public String getFullName() {
        return fullName;
    }

    public String getUserType() {
        return userType;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public String getCarPlate() {
        return carPlate;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}
