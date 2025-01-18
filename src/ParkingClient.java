import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;
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
    private static PrivateKey clientPrivateKey; // Renamed for better understanding
    private static PublicKey clientPublicKey; // Renamed for better understanding public static

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
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
                if (!loggedIn) {
                    System.out.println("1. Register");
                    System.out.println("2. Login");
                } else {
                    System.out.println("3. Reserve");
                    System.out.println("4. Close connection");
                }
                System.out.print("Choose an option: ");
                int choice = scanner.nextInt();
                scanner.nextLine();

                if (choice == 1 && !loggedIn) {
                    // Collect user registration data
                    String fullName;
                    String userType;
                    String phoneNumber;
                    String carPlate;
                    String email;
                    String password;

                    System.out.print("Full Name: ");
                    fullName = scanner.nextLine();

                    // Validate email
                    while (true) {
                        System.out.print("Email: ");
                        email = scanner.nextLine();
                        if (email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
                            break;
                        } else {
                            System.out.println("Email is not in a valid format.");
                        }
                    }

                    // Validate user type
                    while (true) {
                        System.out.print("User Type (employee/visitor): ");
                        userType = scanner.nextLine();
                        if (userType.equals("employee") || userType.equals("visitor")) {
                            break;
                        } else {
                            System.out.println("Invalid user type. Please enter 'employee' or 'visitor'.");
                        }
                    }

                    // Validate phone number
                    while (true) {
                        System.out.print("Phone Number: ");
                        phoneNumber = scanner.nextLine();
                        if (phoneNumber.matches("09\\d{8}")) {
                            break;
                        } else {
                            System.out.println("Phone number must be 10 digits and start with 09.");
                        }
                    }

                    // Validate car plate
                    while (true) {
                        System.out.print("Car Plate: ");
                        carPlate = scanner.nextLine();
                        if (carPlate.matches("\\d{7}")) {
                            break;
                        } else {
                            System.out.println("Car plate must be a 7-digit number.");
                        }
                    }

                    // Validate password
                    while (true) {
                        System.out.print("Password: ");
                        password = scanner.nextLine();
                        if (password.length() >= 10) {
                            break;
                        } else {
                            System.out.println("Password must be at least 10 characters long.");
                        }
                    }

                    User user = new User(fullName, userType, phoneNumber, carPlate, email, password);

                    // Send registration request to server
                    out.writeObject("register");
                    out.writeObject(user);

                    // Receive response from server
                    String response = (String) in.readObject();
                    System.out.println(response);
                } else if (choice == 2 && !loggedIn) {
                    // Collect login data
                    System.out.print("Email: ");
                    String email = scanner.nextLine();
                    System.out.print("Password: ");
                    String password = scanner.nextLine();

                    // Send login request to server
                    out.writeObject("login");
                    out.writeObject(email);
                    out.writeObject(password);

                    // Receive response from server
                    Object response = in.readObject();
                    if (response instanceof User) {
                        User user = (User) response;
                        System.out.println("Login successful!");
                        System.out.println("Email: " + user.getEmail());
                        System.out.println("Full Name: " + user.getFullName());
                        System.out.println("User Type: " + user.getUserType());
                        System.out.println("Phone Number: " + user.getPhoneNumber());
                        System.out.println("Car Plate: " + user.getCarPlate());
                        loggedIn = true;
                        currentUser = user; // Store the logged-in user
                    } else {
                        System.out.println(response);
                    }
                } else if (choice == 3) {
                    System.out.print("Enter parking spot number: ");
                    String parkingSpot = scanner.nextLine();
                    System.out.print("Enter reservation time: ");
                    String time = scanner.nextLine();
                    String reservationData = "ParkingSpot: " + parkingSpot + ", Time: " + time;

                    String creditCardNumber;
                    // Validate Credit Card
                    while (true) {
                        System.out.print("Enter 16-digit credit card number: ");
                        creditCardNumber = scanner.nextLine();
                        if (creditCardNumber.matches("\\d{16}")) {
                            break;
                        } else {
                            System.out.println("Card number must be a 16-digit number.");
                        }
                    }

                    String pin;
                    while (true) {
                        System.out.print("Enter 4-digit PIN: ");
                        pin = scanner.nextLine();
                        if (pin.matches("\\d{4}")) {
                            break;
                        } else {
                            System.out.println("PIN must be a 4-digit number.");
                        }
                    }
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
                } else if (choice == 4) {
                    out.writeObject("close");
                    running = false;
                    LOGGER.info("Client requested to close the connection.");
                }
            }

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidAlgorithmParameterException | SignatureException e) {
            LOGGER.log(Level.SEVERE, "Error in client operation.", e);
        }
        scanner.close();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}