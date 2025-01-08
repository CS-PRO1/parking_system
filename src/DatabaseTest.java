import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Logger;
import java.util.logging.Level;

public class DatabaseTest {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/parking_system";
    private static final String DB_USER = "bravonovember";
    private static final String DB_PASSWORD = "password";
    private static final Logger LOGGER = Logger.getLogger(DatabaseTest.class.getName());

    public static void main(String[] args) {
        Connection conn = null;
        PreparedStatement stmt = null;
        try {
            LOGGER.info("Establishing database connection...");
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            LOGGER.info("Database connection established.");

            String query = "INSERT INTO reservations (user_email, parking_spot, reservation_time) VALUES (?, ?, ?)";
            stmt = conn.prepareStatement(query);
            stmt.setString(1, "testuser@example.com");
            stmt.setString(2, "1");
            stmt.setString(3, "2025-01-07 14:30");

            LOGGER.info("Prepared statement: " + stmt);
            int rowsAffected = stmt.executeUpdate();
            LOGGER.info("Rows affected: " + rowsAffected);
            LOGGER.info("Reservation successfully inserted.");
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "SQL Error: " + e.getErrorCode() + " - " + e.getSQLState(), e);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Unexpected error.", e);
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
                if (conn != null)
                    conn.close();
                LOGGER.info("Database resources closed.");
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error closing database resources.", e);
            }
        }
    }
}
