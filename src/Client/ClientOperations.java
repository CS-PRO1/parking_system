package Client;

import java.io.*;
import java.security.*;
import javax.crypto.*;

import Utilities.EncryptionUtility;
import Utilities.UserModel;

public class ClientOperations {
    private UserModel currentUser;
    private SecretKey sessionKey;
    private PrivateKey clientPrivateKey;
    private UserInputModule uiModule;

    public ClientOperations(SecretKey sessionKey, PrivateKey clientPrivateKey, UserInputModule uiModule) {
        this.sessionKey = sessionKey;
        this.clientPrivateKey = clientPrivateKey;
        this.uiModule = uiModule;
    }

    // Handles new user registration process after validating each input
    public UserModel handleRegistration(ObjectOutputStream out, ObjectInputStream in) throws Exception {
        String fullName = uiModule.getStringInput("Full Name: ");
        String email = uiModule.getValidatedEmail("Email: ");
        String userType = uiModule.getValidatedUserType("UserModel Type (employee/visitor): ");
        String phoneNumber = uiModule.getValidatedPhoneNumber("Phone Number: ");
        String carPlate = uiModule.getValidatedCarPlate("Car Plate: ");
        String password = uiModule.getValidatedPassword("Password: ");

        UserModel user = new UserModel(fullName, userType, phoneNumber, carPlate, email, password);

        out.writeObject("register");
        out.writeObject(user);

        Object response = in.readObject();
        if (response instanceof UserModel) {
            UserModel registeredUser = (UserModel) response;
            System.out.println("Registration and login successful!");
            System.out.println("Email: " + registeredUser.getEmail());
            System.out.println("Full Name: " + registeredUser.getFullName());
            System.out.println("UserModel Type: " + registeredUser.getUserType());
            System.out.println("Phone Number: " + registeredUser.getPhoneNumber());
            System.out.println("Car Plate: " + registeredUser.getCarPlate());
            return registeredUser;
        } else {
            System.out.println(response);
            return null;
        }
    }

    // Handles Login procedure
    public UserModel handleLogin(ObjectOutputStream out, ObjectInputStream in) throws Exception {
        String email = uiModule.getValidatedEmail("Email: ");
        String password = uiModule.getValidatedPassword("Password: ");

        out.writeObject("login");
        out.writeObject(email);
        out.writeObject(password);

        Object response = in.readObject();
        if (response instanceof UserModel) {
            UserModel loggedInUser = (UserModel) response;
            System.out.println("Login successful!");
            System.out.println("Email: " + loggedInUser.getEmail());
            System.out.println("Full Name: " + loggedInUser.getFullName());
            System.out.println("UserModel Type: " + loggedInUser.getUserType());
            System.out.println("Phone Number: " + loggedInUser.getPhoneNumber());
            System.out.println("Car Plate: " + loggedInUser.getCarPlate());
            return loggedInUser;
        } else {
            System.out.println(response);
            return null;
        }
    }
//Handles the reservation request and validates inputs
    public void handleReservation(ObjectOutputStream out, ObjectInputStream in) throws Exception {
        String parkingSpot = uiModule.getStringInput("Enter parking spot number: ");
        String time = uiModule.getStringInput("Enter reservation time: ");
        String reservationData = "ParkingSpot: " + parkingSpot + ", Time: " + time;

        String creditCardNumber = uiModule.getValidatedCreditCard("Enter 16-digit credit card number: ");
        String pin = uiModule.getValidatedPIN("Enter 4-digit PIN: ");
        String paymentData = "CreditCardNumber: " + creditCardNumber + ", PIN: " + pin;

        byte[] encryptedData = EncryptionUtility.encrypt(reservationData, sessionKey);
        byte[] signature = EncryptionUtility.signData(reservationData, clientPrivateKey);

        out.writeObject("reserve");
        out.writeObject(encryptedData);
        out.writeObject(signature);
        out.writeObject(currentUser);

        byte[] encryptedPaymentData = EncryptionUtility.encrypt(paymentData, sessionKey);
        out.writeObject(encryptedPaymentData);

        byte[] encryptedResponse = (byte[]) in.readObject();
        String response = EncryptionUtility.decrypt(encryptedResponse, sessionKey);
        System.out.println(response);
    }

    public void setCurrentUser(UserModel user) {
        this.currentUser = user;
    }
}