package com.reachai.reachscanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reachai.reachscanner.model.CallChain;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class SarifParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Parses SARIF output from CodeQL and extracts call chains
     *
     * @param sarifFile Path to the SARIF results file
     * @return List of call chains showing paths to vulnerable code
     */
    public List<CallChain> parseCallChains(Path sarifFile) throws IOException {
        log.info("Parsing SARIF file: {}", sarifFile);

        List<CallChain> callChains = new ArrayList<>();

        JsonNode root = objectMapper.readTree(sarifFile.toFile());
        JsonNode runs = root.get("runs");

        if (runs == null || !runs.isArray() || runs.isEmpty()) {
            log.warn("No runs found in SARIF file");
            return callChains;
        }

        // Process each run
        for (JsonNode run : runs) {
            JsonNode results = run.get("results");
            if (results == null || !results.isArray()) {
                continue;
            }

            // Process each result (finding)
            for (JsonNode result : results) {
                try {
                    CallChain callChain = extractCallChain(result, run);
                    if (callChain != null) {
                        callChains.add(callChain);
                    }
                } catch (Exception e) {
                    log.error("Error extracting call chain from result: {}", e.getMessage());
                }
            }
        }

        log.info("Extracted {} call chains from SARIF", callChains.size());
        return callChains;
    }

    /**
     * Extracts a single call chain from a SARIF result
     */
    private CallChain extractCallChain(JsonNode result, JsonNode run) {
        List<CallChain.CallStep> steps = new ArrayList<>();

        // Get code flows (data flow paths)
        JsonNode codeFlows = result.get("codeFlows");
        if (codeFlows == null || !codeFlows.isArray() || codeFlows.isEmpty()) {
            return null;
        }

        // Take the first code flow
        JsonNode firstFlow = codeFlows.get(0);
        JsonNode threadFlows = firstFlow.get("threadFlows");

        if (threadFlows == null || !threadFlows.isArray() || threadFlows.isEmpty()) {
            return null;
        }

        JsonNode locations = threadFlows.get(0).get("locations");
        if (locations == null || !locations.isArray()) {
            return null;
        }

        String entryPoint = null;
        String vulnerableSink = null;

        // Extract each step in the data flow
        for (int i = 0; i < locations.size(); i++) {
            JsonNode location = locations.get(i);
            JsonNode physicalLocation = location.get("location").get("physicalLocation");

            if (physicalLocation == null) {
                continue;
            }

            JsonNode artifactLocation = physicalLocation.get("artifactLocation");
            JsonNode region = physicalLocation.get("region");

            if (artifactLocation == null || region == null) {
                continue;
            }

            String fileName = artifactLocation.get("uri").asText();
            int lineNumber = region.has("startLine") ? region.get("startLine").asInt() : 0;

            // Extract snippet if available
            String snippet = "";
            if (region.has("snippet") && region.get("snippet").has("text")) {
                snippet = region.get("snippet").get("text").asText().trim();
            }

            // Extract method/function name from message if available
            String methodName = extractMethodName(location);
            String className = extractClassName(fileName);

            CallChain.CallStep step = CallChain.CallStep.builder()
                    .fileName(fileName)
                    .lineNumber(lineNumber)
                    .methodName(methodName)
                    .className(className)
                    .snippet(snippet)
                    .build();

            steps.add(step);

            // First step is the entry point
            if (i == 0) {
                entryPoint = methodName != null ? methodName : fileName + ":" + lineNumber;
            }

            // Last step is the vulnerable sink
            if (i == locations.size() - 1) {
                vulnerableSink = methodName != null ? methodName : fileName + ":" + lineNumber;
            }
        }

        if (steps.isEmpty()) {
            return null;
        }

        return CallChain.builder()
                .entryPoint(entryPoint)
                .vulnerableSink(vulnerableSink)
                .steps(steps)
                .isReachable(true)
                .build();
    }

    /**
     * Extracts method name from location message or properties
     */
    private String extractMethodName(JsonNode location) {
        // Try to get from message
        if (location.has("message") && location.get("message").has("text")) {
            String message = location.get("message").get("text").asText();
            // Message often contains method name in various formats
            // e.g., "call to readValue" or "UserController.handleRequest"
            return message;
        }

        // Try to get from properties
        if (location.has("properties")) {
            JsonNode properties = location.get("properties");
            if (properties.has("method")) {
                return properties.get("method").asText();
            }
        }

        return "unknown";
    }

    /**
     * Extracts class name from file path
     * Example: src/main/java/com/example/UserController.java -> UserController
     */
    private String extractClassName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return "unknown";
        }

        // Remove file extension
        String withoutExt = fileName.replaceAll("\\.java$", "");

        // Get last part of path
        String[] parts = withoutExt.split("/");
        return parts[parts.length - 1];
    }
}