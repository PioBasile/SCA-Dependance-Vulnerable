package org.example;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Date;

public class CveService {
    private static final HttpClient client = HttpClient.newHttpClient();

    public static String fetchDataFromApi(String url) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        System.out.println("\n\n[" + new Date().toLocaleString() + "] GET " + url);

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("[SUCCESS] => Response code : " + response.statusCode() + " | Response length : " + response.body().length());

            return response.body();
        } catch (Exception e) {
            System.err.println("[ERROR] => Trace : " + e.getMessage());
            return null;
        }
    }
}
