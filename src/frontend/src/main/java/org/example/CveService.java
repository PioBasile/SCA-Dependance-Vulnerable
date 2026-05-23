package org.example;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class CveService {
    private static final Logger logger = LoggerFactory.getLogger("HTTP");
    private static final HttpClient client = HttpClient.newHttpClient();

    public static String fetchDataFromApi(String url) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        logger.info("GET {}", url);

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("{} — {} bytes", response.statusCode(), response.body().length());
            return response.body();
        } catch (Exception e) {
            logger.error("Request failed : {}", e.getMessage());
            return null;
        }
    }
}
