package org.example;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.embed.swing.SwingNode;
import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.stage.Stage;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javax.swing.*;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;
import org.graphstream.ui.graphicGraph.GraphicElement;
import org.graphstream.ui.view.Viewer;
import org.graphstream.ui.view.util.InteractiveElement;
import org.graphstream.ui.swing_viewer.SwingViewer;
import org.graphstream.ui.swing_viewer.ViewPanel;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.cdimascio.dotenv.Dotenv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.awt.Desktop;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class DependencyAnalyzerApp extends Application {

    private Graph graph;
    private ViewPanel viewPanel;
    private String hoveredCveId = null;
    private final Map<String, String> originalStyles = new HashMap<>();
    private Label warningLabel;
    private static final Logger logger = LoggerFactory.getLogger("APP");
    private static final Dotenv dotenv = Dotenv.load();
    private static final String BACKEND_URL = dotenv.get("BACKEND_URL");
    private static final String CPE_API = "/config_nodes_cpe_match/?cpe_criteria=";
    private static final String API = BACKEND_URL + CPE_API;

    private static String formatCpe(String cpe) {
        String[] parts = cpe.split(":");
        if (parts.length >= 6) {
            String vendor = parts[3];
            String product = parts[4];
            String version = parts[5];
            return vendor.equals(product) ? product + " " + version
                                          : vendor + ":" + product + " " + version;
        }
        return cpe;
    }

    private void openCveInBrowser(String cveId) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI("https://www.cve.org/CVERecord?id=" + cveId));
            }
        } catch (Exception e) {
            logger.warn("Cannot open browser for {}: {}", cveId, e.getMessage());
        }
    }

    @Override
    public void start(Stage primaryStage) {
        System.setProperty("org.graphstream.ui", "swing");

        VBox leftSection = new VBox(10);
        Label titleLabel = new Label("SECURITY VULNERABILITIES");
        titleLabel.setTextFill(Color.WHITE);
        titleLabel.setStyle("-fx-font-size: 18px; -fx-font-weight: bold;");
        titleLabel.setPadding(new Insets(10, 0, 0, 10));

        Text descriptionText = new Text(
                "The blue Application node sits at the center, each dependency (green) is connected to it, and every confirmed CVE is attached to its dependency."
                        + "  CVE colour reflects its CVSS base score:"
                        + "  RED — score > 8.5 (high)."
                        + "  ORANGE — score > 6.5 (medium)."
                        + "  GREEN — score ≤ 6.5 (low)."
                        + "  PINK — score estimated by AI."
                        + "  Click any CVE node to open it on cve.org."
        );
        descriptionText.setFill(Color.WHITE);

        TextFlow descriptionTextFlow = new TextFlow(descriptionText);
        descriptionTextFlow.setPrefWidth(360);
        descriptionTextFlow.setPadding(new Insets(0, 10, 10, 10));

        VBox symbolsBox = new VBox(10);
        symbolsBox.setPadding(new Insets(12, 14, 12, 14));
        symbolsBox.setStyle("-fx-background-color: white; -fx-background-radius: 10; -fx-border-color: purple; -fx-border-width: 1; -fx-border-radius: 10;");

        // Row 1: node types
        HBox apiSymbols = new HBox(8);
        apiSymbols.setAlignment(Pos.CENTER_LEFT);
        Label rootNodeLabel = new Label("●");
        rootNodeLabel.setStyle("-fx-font-size: 22px;");
        rootNodeLabel.setTextFill(Color.BLUE);
        Label apiSymbol = new Label("●");
        apiSymbol.setStyle("-fx-font-size: 22px;");
        apiSymbol.setTextFill(Color.web("#006400"));
        Label apiLabel = new Label("Application root  /  Dependency");
        apiLabel.setStyle("-fx-font-size: 12px;");
        apiSymbols.getChildren().addAll(rootNodeLabel, apiSymbol, apiLabel);

        // Row 2: edge
        HBox linkSymbol = new HBox(8);
        linkSymbol.setAlignment(Pos.CENTER_LEFT);
        Label linkLine = new Label("─────");
        linkLine.setStyle("-fx-font-size: 14px;");
        linkLine.setTextFill(Color.BLACK);
        Label linkLabel = new Label("Links Application → Dependency → CVE");
        linkLabel.setStyle("-fx-font-size: 12px;");
        linkSymbol.getChildren().addAll(linkLine, linkLabel);

        // Row 3: CVE severity colours
        HBox vulnSymbols = new HBox(6);
        vulnSymbols.setAlignment(Pos.CENTER_LEFT);
        Label greenSymbol  = new Label("●"); greenSymbol.setStyle("-fx-font-size: 18px;");  greenSymbol.setTextFill(Color.GREEN);
        Label orangeSymbol = new Label("●"); orangeSymbol.setStyle("-fx-font-size: 18px;"); orangeSymbol.setTextFill(Color.ORANGE);
        Label redSymbol    = new Label("●"); redSymbol.setStyle("-fx-font-size: 18px;");    redSymbol.setTextFill(Color.RED);
        Label vulnLabel = new Label("CVE severity: low (≤ 6.5) / medium (> 6.5) / high (> 8.5)");
        vulnLabel.setStyle("-fx-font-size: 12px;");
        vulnSymbols.getChildren().addAll(greenSymbol, orangeSymbol, redSymbol, vulnLabel);

        // Row 4: AI / no score
        HBox aiSymbols = new HBox(6);
        aiSymbols.setAlignment(Pos.CENTER_LEFT);
        Label pinkSymbol = new Label("●"); pinkSymbol.setStyle("-fx-font-size: 18px;"); pinkSymbol.setTextFill(Color.HOTPINK);
        Label graySymbol = new Label("●"); graySymbol.setStyle("-fx-font-size: 18px;"); graySymbol.setTextFill(Color.GRAY);
        Label aiLabel = new Label("AI-predicted score / No score available");
        aiLabel.setStyle("-fx-font-size: 12px;");
        aiSymbols.getChildren().addAll(pinkSymbol, graySymbol, aiLabel);

        symbolsBox.getChildren().addAll(apiSymbols, linkSymbol, vulnSymbols, aiSymbols);

        StackPane symbolsPane = new StackPane(symbolsBox);
        StackPane.setMargin(symbolsBox, new Insets(0, 15, 0, 15));

        Label titleText = new Label("Visualize Data");
        titleText.setTextFill(Color.WHITE);
        titleText.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");
        titleText.setPadding(new Insets(20, 0, 10, 0));
        VBox titleTextContainer = new VBox(titleText);
        titleTextContainer.setAlignment(Pos.CENTER);

        TextField textInputField = new TextField();
        textInputField.setPromptText("Enter the path of the project to analyze");
        textInputField.setMaxWidth(330);
        textInputField.setPadding(new Insets(7, 2, 7, 2));
        VBox InputFieldContainer = new VBox(textInputField);
        InputFieldContainer.setAlignment(Pos.CENTER);

        Button analyzeButton = new Button("ANALYZE");
        analyzeButton.setStyle("-fx-background-color: #4CAF50; -fx-text-fill: white; -fx-background-radius: 10px; -fx-font-size: 15px; -fx-font-weight: bold; -fx-padding: 10 20 10 20;");
        analyzeButton.setPrefWidth(150);
        analyzeButton.setCursor(Cursor.HAND);

        analyzeButton.setOnAction(event -> {
            String projectPath = textInputField.getText();
            if (projectPath == null || projectPath.isEmpty()) return;

            analyzeButton.setDisable(true);
            analyzeButton.setText("ANALYZING…");

            new Thread(() -> {
                try {
                    SwingUtilities.invokeLater(() -> {
                        synchronized (graph) {
                            graph.clear();
                            Node app = graph.addNode("Application");
                            app.setAttribute("ui.label", "Application");
                            app.setAttribute("ui.style", "fill-color: #1e6fbf; size: 40px; text-size: 17px; text-color: black; text-style: bold;");
                        }
                    });

                    String[] syftTarget = SbomExtractor.resolveTarget(projectPath);
                    String resolvedPath = syftTarget[0];
                    String warning      = syftTarget[1];
                    Platform.runLater(() -> {
                        warningLabel.setText(warning != null ? "⚠ " + warning : "");
                        warningLabel.setVisible(warning != null);
                        warningLabel.setManaged(warning != null);
                    });

                    SbomExtractor.ExtractSbom(resolvedPath, 2);
                    File sbomFile = new File("sbom.cyclonedx.json");
                    if (!sbomFile.exists()) return;

                    List<String> cpes = SbomExtractor.extractCpeFromCycloneDx("sbom.cyclonedx.json");

                    for (String cpe : cpes) {
                        try {
                            String encodedCpe = URLEncoder.encode(cpe, StandardCharsets.UTF_8);
                            String result = CveService.fetchDataFromApi(API + encodedCpe);

                            SwingUtilities.invokeLater(() -> {
                                synchronized (graph) {
                                    try {
                                        Node n = graph.getNode(cpe);
                                        if (n == null) {
                                            n = graph.addNode(cpe);
                                            n.setAttribute("ui.label", formatCpe(cpe));
                                        }
                                        String appEdgeId = "Application->" + cpe;
                                        if (graph.getNode("Application") != null && graph.getEdge(appEdgeId) == null) {
                                            graph.addEdge(appEdgeId, "Application", cpe);
                                        }

                                        Double aiScore = null;
                                        List<JsonNode> cveEntries = new ArrayList<>();
                                        try {
                                            ObjectMapper mapper = new ObjectMapper();
                                            JsonNode jsonResponse = mapper.readTree(result);
                                            JsonNode aiNode = jsonResponse.path("ai_prediction");
                                            if (aiNode != null && !aiNode.isMissingNode() && !aiNode.isNull()) {
                                                JsonNode scoreNode = aiNode.path("score");
                                                if (!scoreNode.isMissingNode() && !scoreNode.isNull()) {
                                                    aiScore = scoreNode.asDouble();
                                                }
                                            }
                                            JsonNode vulns = jsonResponse.path("vulnerabilities");
                                            if (vulns.isArray()) {
                                                for (JsonNode v : vulns) {
                                                    if (!v.path("cve_id").asText("").isEmpty()) cveEntries.add(v);
                                                }
                                            }
                                        } catch (Exception ignored) {}

                                        // Dependency node: pink when AI predicted severity (no confirmed CVEs)
                                        String depColor = (aiScore != null) ? "hotpink" : "#00B500";
                                        n.setAttribute("ui.style", "fill-color: " + depColor + "; size: 20px; text-size: 12px;");
                                        if (aiScore != null) {
                                            n.setAttribute("ui.label", String.format("%s (AI: %.1f)", formatCpe(cpe), aiScore));
                                        }

                                        for (JsonNode cve : cveEntries) {
                                            String cveId = cve.path("cve_id").asText();

                                            JsonNode scoreNode = cve.path("base_score");
                                            boolean hasScore = !scoreNode.isMissingNode()
                                                    && !scoreNode.isNull()
                                                    && scoreNode.asDouble() > 0.0;
                                            boolean scoreIsAi = cve.path("score_is_ai").asBoolean(false);
                                            double score = hasScore ? scoreNode.asDouble() : 0.0;
                                            String scoreLabel = hasScore
                                                    ? String.format("%.1f%s", score, scoreIsAi ? " (AI)" : "")
                                                    : "N/A";
                                            String color = scoreIsAi ? "hotpink"
                                                    : !hasScore ? "gray"
                                                    : score > 8.5 ? "red"
                                                    : score > 6.5 ? "orange"
                                                    : "green";

                                            Node cveNode = graph.getNode(cveId);
                                            if (cveNode == null) {
                                                cveNode = graph.addNode(cveId);
                                            }
                                            cveNode.setAttribute("ui.label", String.format("%s (%s)", cveId, scoreLabel));
                                            cveNode.setAttribute("ui.style", "fill-color: " + color + "; size: 16px; text-size: 11px;");

                                            String edgeId = cpe + "->" + cveId;
                                            if (graph.getEdge(edgeId) == null) {
                                                graph.addEdge(edgeId, cpe, cveId);
                                            }
                                        }
                                    } catch (ConcurrentModificationException cme) {
                                        logger.warn("Concurrent modification on node {}", cpe);
                                    }
                                }
                            });

                            Thread.sleep(200);
                        } catch (Exception e) {
                            logger.error("Analysis error on {}: {}", cpe, e.getMessage());
                        }
                    }
                } finally {
                    Platform.runLater(() -> {
                        analyzeButton.setDisable(false);
                        analyzeButton.setText("ANALYZE");
                    });
                }
            }).start();
        });

        HBox buttonBox = new HBox(analyzeButton);
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.setPadding(new Insets(25, 0, 0, 0));

        warningLabel = new Label();
        warningLabel.setTextFill(Color.YELLOW);
        warningLabel.setStyle("-fx-font-size: 11px;");
        warningLabel.setWrapText(true);
        warningLabel.setMaxWidth(330);
        warningLabel.setPadding(new Insets(6, 15, 0, 15));
        warningLabel.setVisible(false);
        warningLabel.setManaged(false);

        VBox mainContent = new VBox(10);
        mainContent.getChildren().addAll(symbolsPane, titleTextContainer, InputFieldContainer, buttonBox, warningLabel);
        leftSection.getChildren().addAll(titleLabel, descriptionTextFlow, mainContent);

        SwingNode swingNode = new SwingNode();
        createGraphViewer(swingNode);

        BorderPane mainLayout = new BorderPane();
        mainLayout.setLeft(leftSection);
        mainLayout.setCenter(swingNode);
        Color customColor = Color.rgb(94, 136, 160, 0.8);
        mainLayout.setBackground(new Background(new BackgroundFill(customColor, CornerRadii.EMPTY, Insets.EMPTY)));

        Scene scene = new Scene(mainLayout, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Dependency Analyzer");
        primaryStage.show();
    }

    private void createGraphViewer(SwingNode swingNode) {
        SwingUtilities.invokeLater(() -> {
            graph = new SingleGraph("Graph");
            graph.setAttribute("ui.stylesheet", "node { text-size: 12px; }");
            Viewer viewer = new SwingViewer(graph, Viewer.ThreadingModel.GRAPH_IN_GUI_THREAD);
            viewer.enableAutoLayout();
            viewPanel = (ViewPanel) viewer.addDefaultView(false);
            swingNode.setContent(viewPanel);

            EnumSet<InteractiveElement> nodeOnly = EnumSet.of(InteractiveElement.NODE);

            viewPanel.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    GraphicElement el = viewPanel.findGraphicElementAt(nodeOnly, e.getX(), e.getY());
                    if (el != null && el.getId().startsWith("CVE-")) {
                        openCveInBrowser(el.getId());
                    }
                }
            });

            viewPanel.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
                @Override
                public void mouseMoved(MouseEvent e) {
                    GraphicElement el = viewPanel.findGraphicElementAt(nodeOnly, e.getX(), e.getY());
                    String newId = (el != null && el.getId().startsWith("CVE-")) ? el.getId() : null;

                    if (Objects.equals(newId, hoveredCveId)) return;

                    // Restore previous hovered node
                    if (hoveredCveId != null) {
                        synchronized (graph) {
                            Node prev = graph.getNode(hoveredCveId);
                            if (prev != null && originalStyles.containsKey(hoveredCveId)) {
                                prev.setAttribute("ui.style", originalStyles.get(hoveredCveId));
                            }
                        }
                    }

                    // Highlight new hovered node
                    if (newId != null) {
                        synchronized (graph) {
                            Node node = graph.getNode(newId);
                            if (node != null) {
                                String original = (String) node.getAttribute("ui.style");
                                originalStyles.put(newId, original);
                                String highlighted = original
                                    .replace("size: 16px", "size: 28px")
                                    .replace("text-size: 11px", "text-size: 14px")
                                    + " stroke-mode: plain; stroke-color: white; stroke-width: 3px;";
                                node.setAttribute("ui.style", highlighted);
                            }
                        }
                        viewPanel.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
                    } else {
                        viewPanel.setCursor(java.awt.Cursor.getDefaultCursor());
                    }

                    hoveredCveId = newId;
                }
            });
        });
    }
}
