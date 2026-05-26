package org.example;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SbomExtractor {
    private static final Logger logger = LoggerFactory.getLogger("SYFT");

    public static void ExtractSbom(String ProjectPath, int Format) {
        try {
            String syftPath = new File("./syft").exists() ? "./syft" : "syft";

            String outputOption = switch (Format) {
                case 1 -> "spdx-json=sbom.spdx.json";
                case 2 -> "cyclonedx-json=sbom.cyclonedx.json";
                default -> throw new IllegalArgumentException("Invalid format : " + Format);
            };

            ProcessBuilder pb = new ProcessBuilder(syftPath, ProjectPath, "-o", outputOption);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                while (reader.readLine() != null) {}
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                logger.info("SBOM generated successfully");
            } else {
                logger.warn("Syft exited with code {}", exitCode);
            }
        } catch (Exception e) {
            logger.error("SBOM extraction failed : {}", e.getMessage());
        }
    }

    public static List<String> extractCpeFromCycloneDx(String filePath) {
        List<String> cpeList = new ArrayList<>();
        try {
            JsonNode root = new ObjectMapper().readTree(new File(filePath));
            JsonNode components = root.path("components");

            if (components.isArray()) {
                for (JsonNode component : components) {

                    JsonNode cpeNode = component.path("cpe");
                    if (!cpeNode.isMissingNode() && !cpeNode.asText().isEmpty()) {
                        cpeList.add(cpeNode.asText());
                    } else {
                        JsonNode cpesNode = component.path("cpes");
                        if (cpesNode.isArray() && !cpesNode.isEmpty()) {
                            cpeList.add(cpesNode.get(0).asText());
                        }
                    }
                }
            }
            logger.info("Parsed SBOM : {} components with CPE found", cpeList.size());
        } catch (Exception e) {
            logger.error("Failed to read SBOM : {}", e.getMessage());
        }
        return cpeList;
    }

    public static String[] resolveTarget(String userPath) {
        File f = new File(userPath);

        if (!f.exists()) {
            throw new IllegalArgumentException("Path doesn't exists : " + userPath);
        }

        if (f.isDirectory()) {
            File pomFile = new File(f, "pom.xml");
            if (pomFile.exists()) {
                logger.info("Maven project found, resolving transitives dependencies");
                try {
                    ProcessBuilder mavenPb = new ProcessBuilder(
                            "mvn", "dependency:copy-dependencies", "-DoutputDirectory=target/dependency"
                    );
                    mavenPb.directory(f);
                    Process mavenProcess = mavenPb.start();
                    mavenProcess.waitFor();
                } catch (Exception e) {
                    logger.warn("Fallback on pom.xml due to an error : {}", e.getMessage());
                }
            }

            File depDir = new File(f, "target/dependency");
            if (depDir.isDirectory() && depDir.list() != null && Objects.requireNonNull(depDir.list()).length > 0) {
                logger.info("Syft scan on complet dependencies tree");
                return new String[]{depDir.getAbsolutePath(), null};
            }
        }

        if (f.isFile()) {
            String name = f.getName().toLowerCase();
            if (name.endsWith(".jar") || name.endsWith(".war")) {
                if (isFatArchive(f)) {
                    logger.info("Fat archive detected: {}", f.getName());
                    return new String[]{userPath, null};
                }

                return new String[]{
                        userPath,
                        "Warning: Plain JAR detected. Transitive dependencies might be missing. " +
                                "Scan the project root directory instead for full transitive coverage via pom.xml."
                };
            }
        }

        return new String[]{userPath, null};
    }

    private static boolean isFatArchive(File jar) {
        try (ZipFile zip = new ZipFile(jar)) {
            return zip.stream().anyMatch(e -> !e.isDirectory() && e.getName().endsWith(".jar"));
        } catch (Exception e) {
            return false;
        }
    }

    private static File extractPomToTemp(File jar) {
        try (ZipFile zip = new ZipFile(jar)) {
            ZipEntry pomEntry = zip.stream()
                .filter(e -> e.getName().startsWith("META-INF/maven/") && e.getName().endsWith("pom.xml"))
                .findFirst()
                .orElse(null);
            if (pomEntry == null) return null;

            File tempDir = Files.createTempDirectory("syft-").toFile();
            File pomFile = new File(tempDir, "pom.xml");
            try (InputStream in = zip.getInputStream(pomEntry);
                 FileOutputStream out = new FileOutputStream(pomFile)) {
                in.transferTo(out);
            }
            return tempDir;
        } catch (Exception e) {
            logger.warn("Could not extract pom.xml from JAR : {}", e.getMessage());
            return null;
        }
    }
}
