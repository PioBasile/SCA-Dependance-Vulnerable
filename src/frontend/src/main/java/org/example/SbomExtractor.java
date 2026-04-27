package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SbomExtractor {

    public static void ExtractSbom(String ProjectPath , int Format) {
        try {
            // Check if local syft exists, otherwise use system syft
            String syftPath = "./syft";
            if (!new File(syftPath).exists()) {
                syftPath = "syft";
            }

            String outputOption;
            switch (Format) {
                case 1:
                    outputOption = "spdx-json=sbom.spdx.json";
                    break;
                case 2:
                    outputOption = "cyclonedx-json=sbom.cyclonedx.json";
                    break;
                default:
                    throw new IllegalArgumentException("Invalid format. Please provide format 1 or 2.");
            }

            // Execute command using ProcessBuilder with list of arguments to handle spaces correctly
            ProcessBuilder processBuilder = new ProcessBuilder(syftPath, ProjectPath, "-o", outputOption);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            // Read output to avoid blocking
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }

            // Wait for the process to complete
            int exitCode = process.waitFor();
            System.out.println("Syft process exited with code " + exitCode);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

    }
    public static List<String> extractCpeFromCycloneDx(String filePath) {
        ObjectMapper objectMapper = new ObjectMapper();
        List<String> cpeList = new ArrayList<>();

        try {
            // Read the JSON file into a JsonNode
            JsonNode rootNode = objectMapper.readTree(new File(filePath));

            // Navigate to the components node
            JsonNode componentsNode = rootNode.path("components");
            System.out.println("Found components: " + (componentsNode.isArray() ? componentsNode.size() : 0));

            // Iterate over each dependency
            if (componentsNode.isArray()) {
                for (JsonNode componentNode : componentsNode) {
                    JsonNode cpeNode = componentNode.path("cpe");
                    if (!cpeNode.isMissingNode() && !cpeNode.asText().isEmpty()) {
                        String cpe = cpeNode.asText();
                        System.out.println("Extracted CPE: " + cpe);
                        cpeList.add(cpe);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading SBOM file: " + e.getMessage());
        }
        return cpeList;
    }

}
