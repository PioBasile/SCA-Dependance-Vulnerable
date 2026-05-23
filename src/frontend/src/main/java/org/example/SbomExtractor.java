package org.example;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class SbomExtractor {
    private static final Logger logger = LoggerFactory.getLogger("SYFT");

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
            if (exitCode == 0) {
                logger.info("SBOM generated successfully");
            } else {
                logger.warn("Syft exited with code {}", exitCode);
            }
        } catch (Exception e) {
            logger.error("SBOM extraction failed: {}", e.getMessage());
        }
    }

    public static List<String> extractCpeFromCycloneDx(String filePath) {
        ObjectMapper objectMapper = new ObjectMapper();
        List<String> cpeList = new ArrayList<>();

        try {
            JsonNode rootNode = objectMapper.readTree(new File(filePath));
            JsonNode componentsNode = rootNode.path("components");
            int total = componentsNode.isArray() ? componentsNode.size() : 0;

            if (componentsNode.isArray()) {
                for (JsonNode componentNode : componentsNode) {
                    JsonNode cpeNode = componentNode.path("cpe");
                    if (!cpeNode.isMissingNode() && !cpeNode.asText().isEmpty()) {
                        cpeList.add(cpeNode.asText());
                    }
                }
            }

            logger.info("Parsed SBOM: {} components, {} with CPE", total, cpeList.size());
        } catch (Exception e) {
            logger.error("Failed to read SBOM: {}", e.getMessage());
        }

        return cpeList;
    }

    public static String[] resolveTarget(String userPath) {
        File f = new File(userPath);

        if (f.isFile()) {
            String name = f.getName().toLowerCase();
            if (name.endsWith(".jar") || name.endsWith(".war") || name.endsWith(".ear")) {
                logger.info("Target is an archive : {}", userPath);
                return new String[]{userPath, null};
            }
        }

        if (f.isDirectory()) {
            File targetDir = new File(f, "target");
            if (targetDir.isDirectory()) {

                File[] jars = targetDir.listFiles(file ->
                    file.isFile()
                    && file.getName().toLowerCase().endsWith(".jar")
                    && !file.getName().endsWith("-sources.jar")
                    && !file.getName().endsWith("-javadoc.jar")
                    && !file.getName().endsWith("-tests.jar")
                );
                if (jars != null && jars.length > 0) {
                    logger.info("Using built JAR : {}", jars[0].getAbsolutePath());
                    return new String[]{jars[0].getAbsolutePath(), null};
                }

                File depDir = new File(targetDir, "dependency");
                if (depDir.isDirectory() && Objects.requireNonNull(depDir.list()).length > 0) {
                    logger.info("Using target/dependency/ : {}", depDir.getAbsolutePath());
                    return new String[]{depDir.getAbsolutePath(), null};
                }
            }

            logger.warn("No built artifact found, falling back to pom.xml (direct deps only) : {}", userPath);
            return new String[]{
                userPath,
                "No built artifact found — scanning pom.xml only (direct dependencies)\n"
                + "Run 'mvn package -DskipTests' for full transitive coverage"
            };
        }

        return new String[]{userPath, null};
    }
}
