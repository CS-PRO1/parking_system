import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

import java.util.logging.Level;
import java.util.logging.Logger;

@SuppressWarnings("unused")
public class ParkingClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingClient.class.getName());
    private static User currentUser;
    private static PublicKey serverPublicKey;
    private static SecretKey sessionKey;
    private static PrivateKey clientPrivateKey;
    private static PublicKey clientPublicKey;

    public static void main(String[] args) {
        UserInputModule uiModule = new UserInputModule();
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            KeyPair clientKeyPair = KeysUtility.generateRSAKeyPair();
            clientPublicKey = clientKeyPair.getPublic();
            clientPrivateKey = clientKeyPair.getPrivate();
            serverPublicKey = (PublicKey) in.readObject();
            LOGGER.info("Received server's public key.");
            out.writeObject(clientPublicKey);
            LOGGER.info("Sent client's public key.");
            KeyPair dhKeyPair = KeysUtility.generateDHKeyPair();
            PublicKey clientDhPublicKey = dhKeyPair.getPublic();
            PrivateKey clientDhPrivateKey = dhKeyPair.getPrivate();
            out.writeObject(clientDhPublicKey);
            PublicKey serverDhPublicKey = (PublicKey) in.readObject();
            LOGGER.info("Received server DH public key.");
            sessionKey = KeysUtility.generateSessionKey(clientDhPrivateKey,
                    serverDhPublicKey);
            LOGGER.info("Key exchange complete.");
            LOGGER.info("Session Key (Client): " +
                    bytesToHex(sessionKey.getEncoded()));
            boolean running = true;
            boolean loggedIn = false;
            while (running) {
                int choice = loggedIn ? uiModule.getMenuChoice("Reserve", "Close connection")
                        : uiModule.getMenuChoice("Register", "Login");

                if (choice == 1 && !loggedIn) {
                    String fullName = uiModule.getStringInput("Full Name: ");
                    String email = uiModule.getValidatedEmail("Email: ");
                    String userType = uiModule.getValidatedUserType("User Type (employee/visitor): ");
                    String phoneNumber = uiModule.getValidatedPhoneNumber("Phone Number: ");
                    String carPlate = uiModule.getValidatedCarPlate("Car Plate: ");
                    String password = uiModule.getValidatedPassword("Password: ");

                    User user = new User(fullName, userType, phoneNumber, carPlate, email, password);

                    out.writeObject("register");
                    out.writeObject(user);

                    Object response = in.readObject();
                    if (response instanceof User) {
                        User registeredUser = (User) response;
                        System.out.println("Registration and login successful!");
                        System.out.println("Email: " + registeredUser.getEmail());
                        System.out.println("Full Name: " + registeredUser.getFullName());
                        System.out.println("User Type: " + registeredUser.getUserType());
                        System.out.println("Phone Number: " + registeredUser.getPhoneNumber());
                        System.out.println("Car Plate: " + registeredUser.getCarPlate());
                        loggedIn = true;
                        currentUser = registeredUser; // Store the logged-in user
                    } else {
                        System.out.println(response);
                    }
                } else if (choice == 2 && !loggedIn) {
                    String email = uiModule.getValidatedEmail("Email: ");
                    String password = uiModule.getValidatedPassword("Password: ");

                    out.writeObject("login");
                    out.writeObject(email);
                    out.writeObject(password);

                    Object response = in.readObject();
                    if (response instanceof User) {
                        User loggedInUser = (User) response;
                        System.out.println("Login successful!");
                        System.out.println("Email: " + loggedInUser.getEmail());
                        System.out.println("Full Name: " + loggedInUser.getFullName());
                        System.out.println("User Type: " + loggedInUser.getUserType());
                        System.out.println("Phone Number: " + loggedInUser.getPhoneNumber());
                        System.out.println("Car Plate: " + loggedInUser.getCarPlate());
                        loggedIn = true;
                        currentUser = loggedInUser; // Store the logged-in user
                    } else {
                        System.out.println(response);
                    }
                } else if (choice == 1 && loggedIn) {
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
                    out.writeObject(signature); // Send the digital signature
                    out.writeObject(currentUser);

                    byte[] encryptedPaymentData = EncryptionUtility.encrypt(paymentData, sessionKey);
                    out.writeObject(encryptedPaymentData);

                    byte[] encryptedResponse = (byte[]) in.readObject();
                    String response = EncryptionUtility.decrypt(encryptedResponse, sessionKey);
                    System.out.println(response);
                } else if (choice == 2 && loggedIn) {
                    out.writeObject("close");
                    running = false;
                    LOGGER.info("Client requested to close the connection.");
                }
            }

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidAlgorithmParameterException | SignatureException e) {
            LOGGER.log(Level.SEVERE, "Error in client operation.", e);
        } finally {
            uiModule.close();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}