package Client;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

import Utilities.EncryptionUtility;
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

    public static void main(String[] args) {
        UserInputModule uiModule = new UserInputModule();
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            KeyExchangeModule keyExchange = new KeyExchangeModule();
            keyExchange.performKeyExchange(socket, out, in);

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