package main;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class WebServiceCaller {
    private static final String SECRET_KEY = "secret";

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/verify", new VerifyHandler());
        server.setExecutor(null);
        server.start();
    }

    static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            InputStream is = exchange.getRequestBody();
            String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            String body = requestBody.trim();
            String receivedMessage = body.split("\"message\":")[1].split(",")[0].replace("\"", "").trim();
            String receivedHmac = body.split("\"hmac\":")[1].replace("}", "").replace("\"", "").trim();


            String generatedHmac = "";
            try {
                generatedHmac = calculateHMAC(receivedMessage, SECRET_KEY);
            } catch (Exception e) {
                e.printStackTrace();
            }

            boolean valid = receivedHmac.equals(generatedHmac);
            String response = valid ? "Payload integrity verified." : "Payload integrity FAILED.";

            System.out.println("Message Received: " + receivedMessage);
            System.out.println("HMAC Received: " + receivedHmac);
            System.out.println("HMAC Generated: " + generatedHmac);
            System.out.println("Integrity Match: " + valid);

            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    public static String calculateHMAC(String data, String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}
