package org.example;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SbomExtractor {
    public static void ExtractSbom(String ProjectPath, int Format) {
        try {
            String syftPath = "./syft";

            if (!new File(syftPath).exists()) {
                syftPath = "syft";
            }

            String outputOption = switch (Format) {
                case 1 -> "spdx-json=sbom.spdx.json";
                case 2 -> "cyclonedx-json=sbom.cyclonedx.json";
                default -> throw new IllegalArgumentException("Invalid format. Please provide format 1 or 2");
            };

            ProcessBuilder processBuilder = new ProcessBuilder(syftPath, ProjectPath, "-o", outputOption);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;

                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }

            int exitCode = process.waitFor();
            System.out.println("Syft process exited with code : " + exitCode);
        } catch (Exception e) {
            System.err.println("Error during SBOM extraction : " + e.getMessage());
        }

    }
    public static List<String> extractCpeFromCycloneDx(String filePath) {
        ObjectMapper objectMapper = new ObjectMapper();
        List<String> cpeList = new ArrayList<>();

        try {
            JsonNode rootNode = objectMapper.readTree(new File(filePath));

            JsonNode componentsNode = rootNode.path("components");
            System.out.println("Found components : " + (componentsNode.isArray() ? componentsNode.size() : 0));

            if (componentsNode.isArray()) {
                for (JsonNode componentNode : componentsNode) {
                    JsonNode cpeNode = componentNode.path("cpe");

                    if (!cpeNode.isMissingNode() && !cpeNode.asText().isEmpty()) {
                        String cpe = cpeNode.asText();
                        System.out.println("Extracted CPE : " + cpe);
                        cpeList.add(cpe);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading SBOM file : " + e.getMessage());
        }

        return cpeList;
    }
}
