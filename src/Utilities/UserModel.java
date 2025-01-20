package Utilities;

import java.io.Serializable;

public class UserModel implements Serializable {
    private String fullName;
    private String userType;
    private String phoneNumber;
    private String carPlate;
    private String email;
    private String password;

    public UserModel(String fullName, String userType, String phoneNumber, String carPlate, String email,
            String password) {
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

    public void printUser() {
        System.out.println("Name: " + this.fullName);
        System.out.println("Email: " + this.email);
        System.out.println("Phone Number: " + this.phoneNumber);
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public void setCarPlate(String carPlate) {
        this.carPlate = carPlate;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
