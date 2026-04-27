package org.example;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.embed.swing.SwingNode;
import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.stage.Stage;
import javafx.geometry.Insets;
import javafx.geometry.Pos;

import javax.swing.*;

import org.example.Services.CveService;
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
import java.util.ConcurrentModificationException;
import java.util.List;



public class DependencyAnalyzerApp extends Application {

    private Graph graph;
    private static final Dotenv dotenv = Dotenv.load();

    @Override
    public void start(Stage primaryStage) {
        System.setProperty("org.graphstream.ui", "swing");

        VBox leftSection = new VBox(10);
        Label titleLabel = new Label("SECURITY VULNERABILITIES");
        titleLabel.setTextFill(Color.WHITE);
        titleLabel.setStyle("-fx-font-size: 18px; -fx-font-weight: bold;");
        titleLabel.setPadding(new Insets(10, 0, 0, 10));

        Text descriptionText = new Text(
                "Each dependency is a node in the graph. Colour reflects the verdict from the backend chain:"
                        + "  RED — a real CVE was confirmed by EUVD / OSV / NVD / GitHub for this version."
                        + "  YELLOW — no real CVE was found, but the local AI model produced a severity hint (the score is shown in the node label, e.g. 'AI: 8.4')."
                        + "  GREEN — no source flagged this dependency and AI did not produce a hint."
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
        apiSymbol.setTextFill(Color.GREEN);
        Label apiLabel = new Label("Dependency nodes colors");
        Region spacer1 = new Region(); spacer1.setPrefWidth(25);
        apiSymbols.getChildren().addAll(rootNodeLabel, apiSymbol, spacer1, apiLabel);

        HBox linkSymbol = new HBox(20);
        linkSymbol.setAlignment(Pos.CENTER);
        Label linkLine = new Label("─");
        linkLine.setStyle("-fx-font-size: 30px;");
        linkLine.setTextFill(Color.BLACK);
        Label linkLabel = new Label("Links between Dependencies and Vulnerabilities");
        Region spacer21 = new Region(); spacer21.setPrefWidth(8);
        linkSymbol.getChildren().addAll(spacer21, linkLine, linkLabel);

        HBox vulnSymbols = new HBox(-2);
        vulnSymbols.setAlignment(Pos.CENTER_LEFT);
        Label greenSymbol = new Label("●"); greenSymbol.setStyle("-fx-font-size: 40px;"); greenSymbol.setTextFill(Color.GREEN);
        Label yellowSymbol = new Label("●"); yellowSymbol.setStyle("-fx-font-size: 40px;"); yellowSymbol.setTextFill(Color.GOLD);
        Label redSymbol = new Label("●"); redSymbol.setStyle("-fx-font-size: 40px;"); redSymbol.setTextFill(Color.RED);
        Label vulnLabel = new Label("Clean / AI-predicted / Confirmed CVE");
        Region spacer3 = new Region(); spacer3.setPrefWidth(5);
        vulnSymbols.getChildren().addAll(greenSymbol, yellowSymbol, redSymbol, spacer3, vulnLabel);
        Region verticalSpace = new Region(); verticalSpace.setPrefHeight(40);
        symbolsBox.getChildren().addAll(apiSymbols, linkSymbol, verticalSpace, vulnSymbols);

        StackPane symbolsPane = new StackPane(symbolsBox);
        StackPane.setMargin(symbolsBox, new Insets(0, 0, 0, 10));
        HBox checkboxContainer = new HBox(10);
        checkboxContainer.setAlignment(Pos.CENTER);
        checkboxContainer.setPadding(new Insets(5, 0, 10, 0));
        CheckBox checkBox = new CheckBox();
        Label checkBoxLabel = new Label("Trace Transitive Vulnerable Dependencies");
        checkBoxLabel.setTextFill(Color.WHITE);
        checkboxContainer.getChildren().addAll(checkBox, checkBoxLabel);

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

            // Guard: disable the button until this run finishes so a second
            // click doesn't spawn a parallel analysis. Re-enabled in finally.
            analyzeButton.setDisable(true);
            analyzeButton.setText("ANALYZING…");

            new Thread(() -> {
                try {
                    SwingUtilities.invokeLater(() -> {
                        synchronized (graph) {
                            graph.clear();
                        }
                    });

                    SbomExtractor.ExtractSbom(projectPath, 2);
                    File sbomFile = new File("sbom.cyclonedx.json");
                    if (!sbomFile.exists()) {
                        return;
                    }

                    List<String> cpes = SbomExtractor.extractCpeFromCycloneDx("sbom.cyclonedx.json");
                    for (String cpe : cpes) {
                        try {
                            System.out.println("Calling Backend for CPE: " + cpe);
                            String encodedCpe = URLEncoder.encode(cpe, StandardCharsets.UTF_8.toString());
                            String backendUrl = dotenv.get("BACKEND_URL", "http://127.0.0.1:8000");
                            String url = backendUrl + "/config_nodes_cpe_match/?cpe_criteria=" + encodedCpe;
                            String result = CveService.fetchDataFromApi(url);
                            System.out.println("Backend result: " + result);

                            SwingUtilities.invokeLater(() -> {
                                synchronized (graph) {
                                    try {
                                        Node n = graph.getNode(cpe);
                                        if (n == null) {
                                            n = graph.addNode(cpe);
                                            n.setAttribute("ui.label", cpe);
                                        }

                                        // Three tiers:
                                        //   found == true                       → RED  (real CVE confirmed)
                                        //   found == false + ai_prediction set  → YELLOW (AI severity hint)
                                        //   otherwise                            → GREEN (clean)
                                        boolean isVulnerable = false;
                                        Double aiScore = null;
                                        try {
                                            ObjectMapper mapper = new ObjectMapper();
                                            JsonNode jsonResponse = mapper.readTree(result);
                                            if (jsonResponse.has("found") && jsonResponse.get("found").asBoolean()) {
                                                isVulnerable = true;
                                            }
                                            JsonNode aiNode = jsonResponse.path("ai_prediction");
                                            if (aiNode != null && !aiNode.isMissingNode() && !aiNode.isNull()) {
                                                JsonNode scoreNode = aiNode.path("score");
                                                if (!scoreNode.isMissingNode() && !scoreNode.isNull()) {
                                                    aiScore = scoreNode.asDouble();
                                                }
                                            }
                                        } catch (Exception e) {
                                            isVulnerable = false;
                                        }

                                        if (isVulnerable) {
                                            n.setAttribute("ui.style", "fill-color: red; size: 25px; text-size: 15px;");
                                            System.out.println("VULNERABILITY DETECTED for " + cpe);
                                        } else if (aiScore != null) {
                                            // AI predicted severity but no real CVE was confirmed.
                                            // Surface the score directly in the node label so the
                                            // user can tell at a glance how confident the model is.
                                            n.setAttribute("ui.style", "fill-color: gold; size: 22px; text-size: 13px;");
                                            n.setAttribute("ui.label", String.format("%s  (AI: %.1f)", cpe, aiScore));
                                            System.out.printf("AI HINT for %s: predicted CVSS %.1f (no real CVE)%n", cpe, aiScore);
                                        } else {
                                            n.setAttribute("ui.style", "fill-color: green; size: 20px; text-size: 12px;");
                                        }
                                    } catch (ConcurrentModificationException cme) {
                                        System.err.println("Concurrent modification detected for " + cpe + ", will retry on next event");
                                    }
                                }
                            });

                            Thread.sleep(200);
                        } catch (Exception e) {
                            e.printStackTrace();
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
        mainContent.getChildren().addAll(symbolsPane, titleTextContainer, InputFieldContainer, checkboxContainer, buttonBox);
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

    public static void main(String[] args) {
        launch(args);
    }
}
