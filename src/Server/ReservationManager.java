package Server;

import javax.crypto.*;

import Utilities.DatabaseManager;
import Utilities.EncryptionUtility;
import Utilities.UserModel;

import java.security.*;

public class ReservationManager {
    // Receives the reservation request and attempts to verify and execute it
    public byte[] handleReservation(String reservationData, String paymentData, UserModel user, SecretKey sessionKey,
            PublicKey clientPublicKey, byte[] signature)
            throws Exception {
        String userEmail = user.getEmail();
        if (EncryptionUtility.verifySignature(reservationData, signature, clientPublicKey)) {
            String[] parts = reservationData.split(", ");
            if (parts.length == 2
                    && new DatabaseManager().isSpotReserved(parts[0].split(": ")[1], parts[1].split(": ")[1])) {
                return EncryptionUtility.encrypt("Spot is already reserved.", sessionKey);
            } else {
                String[] paymentParts = paymentData.split(", ");
                boolean success = paymentParts.length == 2 &&
                        new DatabaseManager().processPayment(paymentParts[0].split(": ")[1],
                                paymentParts[1].split(": ")[1])
                        &&
                        new DatabaseManager().reserveSpot(userEmail, parts[0].split(": ")[1], parts[1].split(": ")[1]);
                new DatabaseManager().logActivity(userEmail, reservationData, EncryptionUtility.bytesToHex(signature));
                return EncryptionUtility.encrypt(
                        success ? "Reservation and payment successful!" : "Failed to reserve spot or process payment.",
                        sessionKey);
            }
        } else {
            return EncryptionUtility.encrypt("Invalid signature.", sessionKey);
        }
    }

}