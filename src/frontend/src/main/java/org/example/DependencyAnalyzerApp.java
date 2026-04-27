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
import org.graphstream.ui.view.Viewer;
import org.graphstream.ui.swing_viewer.SwingViewer;
import org.graphstream.ui.swing_viewer.ViewPanel;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.cdimascio.dotenv.Dotenv;
import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;

public class DependencyAnalyzerApp extends Application {

    private Graph graph;
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
        );
        descriptionText.setFill(Color.WHITE);

        TextFlow descriptionTextFlow = new TextFlow(descriptionText);
        descriptionTextFlow.setPrefWidth(360);
        descriptionTextFlow.setPadding(new Insets(0, 10, 10, 10));

        VBox symbolsBox = new VBox(-30);
        symbolsBox.setPadding(new Insets(-10, 10, 10, 10));
        symbolsBox.setStyle("-fx-background-color: white; -fx-background-radius: 10; -fx-border-color: purple; -fx-border-width: 1; -fx-border-radius: 10;");

        HBox apiSymbols = new HBox(-10);
        apiSymbols.setAlignment(Pos.CENTER_LEFT);
        Label rootNodeLabel = new Label("●");
        rootNodeLabel.setStyle("-fx-font-size: 60px;");
        rootNodeLabel.setTextFill(Color.BLUE);
        Label apiSymbol = new Label("●");
        apiSymbol.setStyle("-fx-font-size: 60px;");
        apiSymbol.setTextFill(Color.web("#006400"));
        Label apiLabel = new Label("Application root  /  Dependency");
        Region spacer1 = new Region(); spacer1.setPrefWidth(25);
        apiSymbols.getChildren().addAll(rootNodeLabel, apiSymbol, spacer1, apiLabel);

        HBox linkSymbol = new HBox(20);
        linkSymbol.setAlignment(Pos.CENTER);
        Label linkLine = new Label("─");
        linkLine.setStyle("-fx-font-size: 30px;");
        linkLine.setTextFill(Color.BLACK);
        Label linkLabel = new Label("Links Application → Dependency → CVE");
        Region spacer21 = new Region(); spacer21.setPrefWidth(8);
        linkSymbol.getChildren().addAll(spacer21, linkLine, linkLabel);

        HBox vulnSymbols = new HBox(-2);
        vulnSymbols.setAlignment(Pos.CENTER_LEFT);
        Label greenSymbol = new Label("●"); greenSymbol.setStyle("-fx-font-size: 40px;"); greenSymbol.setTextFill(Color.GREEN);
        Label yellowSymbol = new Label("●"); yellowSymbol.setStyle("-fx-font-size: 40px;"); yellowSymbol.setTextFill(Color.ORANGE);
        Label redSymbol = new Label("●"); redSymbol.setStyle("-fx-font-size: 40px;"); redSymbol.setTextFill(Color.RED);
        Label vulnLabel = new Label("CVE severity: low (≤ 6.5) / medium (> 6.5) / high (> 8.5)");
        Region spacer3 = new Region(); spacer3.setPrefWidth(5);
        vulnSymbols.getChildren().addAll(greenSymbol, yellowSymbol, redSymbol, spacer3, vulnLabel);
        Region verticalSpace = new Region(); verticalSpace.setPrefHeight(40);
        symbolsBox.getChildren().addAll(apiSymbols, linkSymbol, verticalSpace, vulnSymbols);

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

                    SbomExtractor.ExtractSbom(projectPath, 2);
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

                                        n.setAttribute("ui.style", "fill-color: #00B500; size: 20px; text-size: 12px;");
                                        if (aiScore != null) {
                                            n.setAttribute("ui.label", String.format("%s (AI: %.1f)", formatCpe(cpe), aiScore));
                                        }

                                        for (JsonNode cve : cveEntries) {
                                            String cveId = cve.path("cve_id").asText();
                                            double score = cve.path("base_score").asDouble(0.0);
                                            String color = score > 8.5 ? "red" : score > 6.5 ? "orange" : "green";

                                            Node cveNode = graph.getNode(cveId);
                                            if (cveNode == null) {
                                                cveNode = graph.addNode(cveId);
                                            }
                                            cveNode.setAttribute("ui.label", String.format("%s (%.1f)", cveId, score));
                                            cveNode.setAttribute("ui.style", "fill-color: " + color + "; size: 16px; text-size: 11px;");

                                            String edgeId = cpe + "->" + cveId;
                                            if (graph.getEdge(edgeId) == null) {
                                                graph.addEdge(edgeId, cpe, cveId);
                                            }
                                        }
                                    } catch (ConcurrentModificationException cme) {
                                        System.err.println("Concurrent modification detected for " + cpe + ", will retry on next event");
                                    }
                                }
                            });

                            Thread.sleep(200);
                        } catch (Exception e) {
                            System.err.println("Error during analyse : " + e.getMessage());
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

        VBox mainContent = new VBox(10);
        mainContent.getChildren().addAll(symbolsPane, titleTextContainer, InputFieldContainer, buttonBox);
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
            ViewPanel viewPanel = (ViewPanel) viewer.addDefaultView(false);
            swingNode.setContent(viewPanel);
        });
    }
}
