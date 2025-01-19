package Server;

import java.io.*;
import java.net.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;
import java.util.logging.Level;

public class ParkingServer {
    private static final int PORT = 3000;
    private static final Logger LOGGER = Logger.getLogger(ParkingServer.class.getName());

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            LOGGER.info("Parking Server is running on port " + PORT);
            // Thread pool to set how many clients can be handled at once
            ExecutorService executor = Executors.newFixedThreadPool(10);

            // Execution loop
            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    executor.execute(() -> new ClientHandler(clientSocket).initializeHandler());
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error accepting client connection.", e);
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error starting server.", e);
        }
    }
}