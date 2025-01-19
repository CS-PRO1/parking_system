package Client;

import java.io.*;
import java.net.*;
import Utilities.UserModel;

import java.util.logging.Level;
import java.util.logging.Logger;

public class ParkingClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingClient.class.getName());
    private static UserModel currentUser;

    public static void main(String[] args) {
        // Creating an instance of the user input module to receive user inputs
        UserInputModule uiModule = new UserInputModule();
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            // Creating an instance of the key echange module to generate keys and perform
            // handshake with the server
            KeyExchangeModule keyExchange = new KeyExchangeModule();
            keyExchange.performKeyExchange(socket, out, in);
            // Creating an instance of the client operation module to handle the client's
            // requests
            ClientOperations ops = new ClientOperations(
                    keyExchange.getSessionKey(),
                    keyExchange.getClientPrivateKey(),
                    uiModule);

            uiModule.handleUserInput(currentUser, ops, out, in, LOGGER);

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in client operation.", e);
        } finally {
            uiModule.close();
        }
    }
}