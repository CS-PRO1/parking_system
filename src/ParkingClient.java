
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;

import utilities.CertificateAuthority;
import utilities.EncryptionUtility;
import utilities.KeysUtility;

public class ParkingClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingClient.class.getName());
    private static User currentUser;
    private static PublicKey serverPublicKey;
    private static SecretKey sessionKey;
    private static KeyPair clientKeyPair;
    private static KeyPair dhKeyPair;
    private static String clientCertificate;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            performKeyExchange(out, in);
            requestCertificate(out, in); // Request Certificate from CA

            boolean running = true;
            boolean loggedIn = false;

            while (running) {
                if (!loggedIn) {
                    promptUser(scanner, "1. Register\n2. Login");
                } else {
                    promptUser(scanner, "3. Reserve\n4. Close connection");
                }

                int choice = scanner.nextInt();
                scanner.nextLine();

                if (choice == 1 && !loggedIn) {
                    registerUser(scanner, out, in);
                } else if (choice == 2 && !loggedIn) {
                    loginUser(scanner, out, in);
                } else if (choice == 3) {
                    reserveSpot(scanner, out, in);
                } else if (choice == 4) {
                    closeConnection(out);
                    running = false;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in client operation.", e);
        }
        scanner.close();
    }

    private static void performKeyExchange(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException, GeneralSecurityException {
        clientKeyPair = KeysUtility.generateRSAKeyPair();
        out.writeObject(clientKeyPair.getPublic());
        serverPublicKey = (PublicKey) in.readObject();

        dhKeyPair = KeysUtility.generateDHKeyPair();
        out.writeObject(dhKeyPair.getPublic());

        PublicKey serverDhPublicKey = (PublicKey) in.readObject();
        sessionKey = KeysUtility.generateSessionKey(dhKeyPair.getPrivate(), serverDhPublicKey);
        LOGGER.info("Key exchange complete.");
    }

    private static void requestCertificate(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, GeneralSecurityException, ClassNotFoundException {
        CertificateAuthority ca = new CertificateAuthority();
        byte[] publicKeyBytes = clientKeyPair.getPublic().getEncoded();
        String csr = Base64.getEncoder().encodeToString(publicKeyBytes);
        String signedCSR = ca.signCSR(csr);
        out.writeObject(signedCSR);
        clientCertificate = signedCSR;
        LOGGER.info("Certificate received from CA.");
    }

    private static void promptUser(Scanner scanner, String options) {
        System.out.print(options);
        System.out.print("Choose an option: ");
    }

    private static void registerUser(Scanner scanner, ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        String fullName, userType, phoneNumber, carPlate, email, password;
        System.out.print("Full Name: ");
        fullName = scanner.nextLine();

        while (true) {
            System.out.print("Email: ");
            email = scanner.nextLine();
            if (email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
                break;
            } else {
                System.out.println("Email is not in a valid format.");
            }
        }

        while (true) {
            System.out.print("User Type (employee/visitor): ");
            userType = scanner.nextLine();
            if (userType.equals("employee") || userType.equals("visitor")) {
                break;
            } else {
                System.out.println("Invalid user type. Please enter 'employee' or 'visitor'.");
            }
        }

        while (true) {
            System.out.print("Phone Number: ");
            phoneNumber = scanner.nextLine();
            if (phoneNumber.matches("09\\d{8}")) {
                break;
            } else {
                System.out.println("Phone number must be 10 digits and start with 09.");
            }
        }

        while (true) {
            System.out.print("Car Plate: ");
            carPlate = scanner.nextLine();
            if (carPlate.matches("\\d{7}")) {
                break;
            } else {
                System.out.println("Car plate must be a 7-digit number.");
            }
        }

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
        out.writeObject("register");
        out.writeObject(user);
        System.out.println((String) in.readObject());
    }

    private static void loginUser(Scanner scanner, ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        System.out.print("Email: ");
        String email = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();

        out.writeObject("login");
        out.writeObject(email);
        out.writeObject(password);

        // Client sends its certificate to the server for validation
        out.writeObject(clientCertificate);

        Object response = in.readObject();
        if (response instanceof User) {
            currentUser = (User) response;
            System.out.println("Login successful!");
        } else {
            System.out.println(response);
        }
    }

    private static void reserveSpot(Scanner scanner, ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException, GeneralSecurityException {
        System.out.print("Enter parking spot number: ");
        String parkingSpot = scanner.nextLine();
        System.out.print("Enter reservation time: ");
        String time = scanner.nextLine();
        String reservationData = "ParkingSpot: " + parkingSpot + ", Time: " + time;

        System.out.print("Enter 16-digit credit card number: ");
        String creditCardNumber = scanner.nextLine();
        System.out.print("Enter 4-digit PIN: ");
        String pin = scanner.nextLine();
        String paymentData = "CreditCardNumber: " + creditCardNumber + ", PIN: " + pin;

        byte[] encryptedData = EncryptionUtility.encrypt(reservationData, sessionKey);
        byte[] signature = EncryptionUtility.signData(reservationData, clientKeyPair.getPrivate());

        out.writeObject("reserve");
        out.writeObject(encryptedData);
        out.writeObject(signature);
        out.writeObject(currentUser);

        byte[] encryptedPaymentData = EncryptionUtility.encrypt(paymentData, sessionKey);
        out.writeObject(encryptedPaymentData);

        // Client includes certificate in reservation data for validation
        out.writeObject(clientCertificate);

        byte[] encryptedResponse = (byte[]) in.readObject();
        String response = EncryptionUtility.decrypt(encryptedResponse, sessionKey);
        System.out.println(response);
    }

    private static void closeConnection(ObjectOutputStream out) throws IOException {
        out.writeObject("close");
        LOGGER.info("Client requested to close the connection.");
    }
}
