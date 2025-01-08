// import java.io.*;
// import java.net.*;
// import java.util.Scanner;

// public class ParkingClient {
//     private static final String SERVER_ADDRESS = "localhost";
//     private static final int SERVER_PORT = 3000;

//     public static void main(String[] args) {
//         try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
//                 ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
//                 ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
//                 Scanner scanner = new Scanner(System.in)) {

//             System.out.println("1. Register");
//             System.out.println("2. Login");
//             System.out.print("Choose an option: ");
//             int choice = scanner.nextInt();
//             scanner.nextLine(); // consume newline

//             if (choice == 1) {
//                 // Collect user registration data
//                 String fullName;
//                 String userType;
//                 String phoneNumber;
//                 String carPlate;
//                 String email;
//                 String password;

//                 System.out.print("Full Name: ");
//                 fullName = scanner.nextLine();

//                 // Validate email
//                 while (true) {
//                     System.out.print("Email: ");
//                     email = scanner.nextLine();
//                     if (email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
//                         break;
//                     } else {
//                         System.out.println("Email is not in a valid format.");
//                     }
//                 }

//                 // Validate user type
//                 while (true) {
//                     System.out.print("User Type (employee/visitor): ");
//                     userType = scanner.nextLine();
//                     if (userType.equals("employee") || userType.equals("visitor")) {
//                         break;
//                     } else {
//                         System.out.println("Invalid user type. Please enter 'employee' or 'visitor'.");
//                     }
//                 }

//                 // Validate phone number
//                 while (true) {
//                     System.out.print("Phone Number: ");
//                     phoneNumber = scanner.nextLine();
//                     if (phoneNumber.matches("09\\d{8}")) {
//                         break;
//                     } else {
//                         System.out.println("Phone number must be 10 digits and start with 09.");
//                     }
//                 }

//                 // Validate car plate
//                 while (true) {
//                     System.out.print("Car Plate: ");
//                     carPlate = scanner.nextLine();
//                     if (carPlate.matches("\\d{7}")) {
//                         break;
//                     } else {
//                         System.out.println("Car plate must be a 7-digit number.");
//                     }
//                 }

//                 // Validate password
//                 while (true) {
//                     System.out.print("Password: ");
//                     password = scanner.nextLine();
//                     if (password.length() >= 10) {
//                         break;
//                     } else {
//                         System.out.println("Password must be at least 10 characters long.");
//                     }
//                 }

//                 User user = new User(fullName, userType, phoneNumber, carPlate, email, password);

//                 // Send registration request to server
//                 out.writeObject("register");
//                 out.writeObject(user);

//                 // Receive response from server
//                 String response = (String) in.readObject();
//                 System.out.println(response);
//             } else if (choice == 2) {
//                 // Collect login data
//                 System.out.print("Email: ");
//                 String email = scanner.nextLine();
//                 System.out.print("Password: ");
//                 String password = scanner.nextLine();

//                 // Send login request to server
//                 out.writeObject("login");
//                 out.writeObject(email);
//                 out.writeObject(password);

//                 // Receive response from server
//                 Object response = in.readObject();
//                 if (response instanceof User) {
//                     User user = (User) response;
//                     System.out.println("Login successful!");
//                     System.out.println("Email: " + user.getEmail());
//                     System.out.println("Full Name: " + user.getFullName());
//                     System.out.println("User Type: " + user.getUserType());
//                     System.out.println("Phone Number: " + user.getPhoneNumber());
//                     System.out.println("Car Plate: " + user.getCarPlate());
//                 } else {
//                     System.out.println(response);
//                 }
//             }

//         } catch (IOException | ClassNotFoundException e) {
//             e.printStackTrace();
//         }
//     }
// }
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.Logger;
import java.util.logging.Level;

public class ParkingClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingClient.class.getName());

    private static User currentUser; // Global variable to store the current user

    public static void main(String[] args) {
        Socket socket = null;
        ObjectOutputStream out = null;
        ObjectInputStream in = null;
        Scanner scanner = new Scanner(System.in);

        try {
            socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            // Key exchange
            LOGGER.info("Starting key exchange...");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            PublicKey clientPublicKey = keyPair.getPublic();
            PrivateKey clientPrivateKey = keyPair.getPrivate();

            // Send client public key to server and receive server public key
            out.writeObject(clientPublicKey);
            PublicKey serverPublicKey = (PublicKey) in.readObject();
            LOGGER.info("Received server public key.");

            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(clientPrivateKey);
            keyAgree.doPhase(serverPublicKey, true);
            byte[] sharedSecret = keyAgree.generateSecret();
            SecretKeySpec sessionKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
            LOGGER.info("Key exchange complete.");
            LOGGER.info("Session Key (Client): " + bytesToHex(sessionKey.getEncoded()));

            boolean running = true;
            boolean loggedIn = false;
            while (running) {
                if (!loggedIn) {
                    System.out.println("1. Register");
                    System.out.println("2. Login");
                }
                else{
                System.out.println("3. Reserve");
                System.out.println("4. Close connection");
                }
                System.out.print("Choose an option: ");
                int choice = scanner.nextInt();
                scanner.nextLine(); // consume newline

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
                    // Encrypt and send reservation data
                    System.out.print("Enter parking spot number: ");
                    String parkingSpot = scanner.nextLine();
                    System.out.print("Enter reservation time: ");
                    String time = scanner.nextLine();
                    String reservationData = "ParkingSpot: " + parkingSpot + ", Time: " + time;

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                    byte[] iv = cipher.getIV(); // Get IV
                    byte[] encryptedData = cipher.doFinal(reservationData.getBytes());

                    out.writeObject("reserve");
                    out.writeObject(iv); // Send IV
                    out.writeObject(encryptedData);

                    // Send the User object
                    out.writeObject(currentUser);

                    // Receive encrypted response from server
                    byte[] encryptedResponse = (byte[]) in.readObject();
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
                    byte[] decryptedResponse = cipher.doFinal(encryptedResponse);
                    String response = new String(decryptedResponse);
                    System.out.println(response);
                }

                else if (choice == 4) {
                    out.writeObject("close");
                    running = false;
                    LOGGER.info("Client requested to close the connection.");
                }
                
                

            }

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in client operation.", e);
        } finally {
            try {
                if (out != null)
                    out.close();
                if (in != null)
                    in.close();
                if (socket != null)
                    socket.close();
                scanner.close();
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error closing resources.", e);
            }
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
