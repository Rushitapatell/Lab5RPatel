package main;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SimpleHttpServer {
    private static final String SECRET_KEY = "secret";

    public static String calculateHMAC(String data, String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    public static void main(String[] args) {
        try {
            String message = "This is a secure message.";
            String hmac = calculateHMAC(message, SECRET_KEY);

            String json = "{ \"message\": \"" + message + "\", \"hmac\": \"" + hmac + "\" }";

            URL url = new URL("http://localhost:8000/verify");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");

            OutputStream os = conn.getOutputStream();
            os.write(json.getBytes(StandardCharsets.UTF_8));
            os.flush();
            os.close();

            System.out.println("Message Sent: " + message);
            System.out.println("HMAC Sent: " + hmac);

            conn.getInputStream().close(); // To trigger the request
            conn.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
