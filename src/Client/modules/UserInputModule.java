package Client.modules;

import java.io.*;
import java.util.Scanner;
import java.util.logging.Logger;

import Utilities.UserModel;

public class UserInputModule {
    private Scanner scanner;

    public UserInputModule() {
        this.scanner = new Scanner(System.in);
    }

    // Method to display the options to the user and handle the inputs
    public void handleUserInput(UserModel currentUser, ClientOperations ops,
            ObjectOutputStream out, ObjectInputStream in, Logger LOGGER) throws Exception {
        boolean running = true;
        boolean loggedIn = false;
        while (running) {
            int choice = loggedIn ? this.getMenuChoice("Reserve", "Close connection")
                    : this.getMenuChoice("Login", "Register", "Close connection");

            if (choice == 1 && !loggedIn) {
                UserModel loggedInUser = ops.handleLogin(out, in);
                if (loggedInUser != null) {
                    loggedIn = true;
                    currentUser = loggedInUser;
                    ops.setCurrentUser(currentUser);
                }
            } else if (choice == 2 && !loggedIn) {
                UserModel newUser = ops.handleRegistration(out, in);
                if (newUser != null) {
                    loggedIn = true;
                    currentUser = newUser;
                    ops.setCurrentUser(currentUser);
                }
            } else if (choice == 1 && loggedIn) {
                ops.handleReservation(out, in);
            } else if ((choice == 2 && loggedIn) || (choice == 3 && !loggedIn)) {
                out.writeObject("close");
                running = false;
                LOGGER.info("Client requested to close the connection.");
            }
        }
    }

    // General string input getter
    public String getStringInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }

    // Validated email input
    public String getValidatedEmail(String prompt) {
        while (true) {
            String email = getStringInput(prompt);
            if (email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
                return email;
            }
            System.out.println("Email is not in a valid format.");
        }
    }

    // Validated user type input
    public String getValidatedUserType(String prompt) {
        while (true) {
            String userType = getStringInput(prompt);
            if ("employee".equalsIgnoreCase(userType) || "visitor".equalsIgnoreCase(userType)) {
                return userType.toLowerCase();
            }
            System.out.println("Invalid user type. Please enter 'employee' or 'visitor'.");
        }
    }

    // Validated phone number input
    public String getValidatedPhoneNumber(String prompt) {
        while (true) {
            String phoneNumber = getStringInput(prompt);
            if (phoneNumber.matches("09\\d{8}")) {
                return phoneNumber;
            }
            System.out.println("Phone number must be 10 digits and start with 09.");
        }
    }

    // Validated car plate input
    public String getValidatedCarPlate(String prompt) {
        while (true) {
            String carPlate = getStringInput(prompt);
            if (carPlate.matches("\\d{7}")) {
                return carPlate;
            }
            System.out.println("Car plate must be a 7-digit number.");
        }
    }

    // Validated password input
    public String getValidatedPassword(String prompt) {
        while (true) {
            String password = getStringInput(prompt);
            if (password.length() >= 10) {
                return password;
            }
            System.out.println("Password must be at least 10 characters long.");
        }
    }

    // Validated credit card input
    public String getValidatedCreditCard(String prompt) {
        while (true) {
            String creditCard = getStringInput(prompt);
            if (creditCard.matches("\\d{16}")) {
                return creditCard;
            }
            System.out.println("Card number must be a 16-digit number.");
        }
    }

    // Validated PIN input
    public String getValidatedPIN(String prompt) {
        while (true) {
            String pin = getStringInput(prompt);
            if (pin.matches("\\d{4}")) {
                return pin;
            }
            System.out.println("PIN must be a 4-digit number.");
        }
    }

    // Menu selection input
    public int getMenuChoice(String... options) {
        for (int i = 0; i < options.length; i++) {
            System.out.println((i + 1) + ". " + options[i]);
        }
        while (true) {
            System.out.print("Choose an option: ");
            if (scanner.hasNextInt()) {
                int choice = scanner.nextInt();
                scanner.nextLine(); // consume newline
                if (choice > 0 && choice <= options.length) {
                    return choice;
                }
            } else {
                scanner.nextLine(); // clear the input buffer
            }
            System.out.println("Invalid option. Please try again.");
        }
    }

    public void close() {
        scanner.close();
    }
}