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
            int total = components.isArray() ? components.size() : 0;

            if (components.isArray()) {
                for (JsonNode component : components) {
                    JsonNode cpe = component.path("cpe");
                    if (!cpe.isMissingNode() && !cpe.asText().isEmpty()) {
                        cpeList.add(cpe.asText());
                    }
                }
            }
            logger.info("Parsed SBOM : {} components, {} with CPE", total, cpeList.size());
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
                if (isFatArchive(f)) {
                    logger.info("Fat archive detected : {}", f.getName());
                    return new String[]{userPath, null};
                }
                File tempDir = extractPomToTemp(f);
                if (tempDir != null) {
                    logger.warn("Plain JAR — extracted pom.xml for dependency scan : {}", f.getName());
                    return new String[]{
                        tempDir.getAbsolutePath(),
                        "Plain JAR detected — scanning embedded pom.xml only (direct dependencies).\n"
                        + "Use a fat JAR or run 'mvn dependency:copy-dependencies' for full transitive coverage."
                    };
                }
                logger.info("Target is an archive : {}", userPath);
                return new String[]{userPath, null};
            }
        }

        if (f.isDirectory()) {
            File depDir = new File(f, "target/dependency");
            String[] depContents = depDir.list();
            if (depDir.isDirectory() && depContents != null && depContents.length > 0) {
                logger.info("Using target/dependency/ : {}", depDir.getAbsolutePath());
                return new String[]{depDir.getAbsolutePath(), null};
            }

            logger.warn("No built artifact found, falling back to pom.xml (direct deps only) : {}", userPath);
            return new String[]{
                userPath,
                "No built artifact found — scanning pom.xml only (direct dependencies)\n"
                + "Run 'mvn dependency:copy-dependencies -DoutputDirectory=target/dependency' for full transitive coverage"
            };
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
