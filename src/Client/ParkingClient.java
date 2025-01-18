package Client;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

import Utilities.KeysUtility;
import Utilities.UserModel;

import java.util.logging.Level;
import java.util.logging.Logger;

@SuppressWarnings("unused")
public class ParkingClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingClient.class.getName());
    private static UserModel currentUser;
    private static PublicKey serverPublicKey;
    private static SecretKey sessionKey;
    private static PrivateKey clientPrivateKey;
    private static PublicKey clientPublicKey;

    public static void main(String[] args) throws Exception {
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

            ClientOperations ops = new ClientOperations(sessionKey, clientPrivateKey, uiModule);
            boolean running = true;
            boolean loggedIn = false;
            while (running) {
                int choice = loggedIn ? uiModule.getMenuChoice("Reserve", "Close connection")
                        : uiModule.getMenuChoice("Login", "Register", "Close connection");

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

        } catch (Exception e) {
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