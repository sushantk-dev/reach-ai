package com.reachai.reachscanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reachai.reachscanner.model.CallChain;
import com.reachai.reachscanner.model.VulnerableDependency;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for communicating with the Python AI Explanation Service
 * Sends vulnerability data and receives AI-generated explanations
 * Iteration 4: Now handles exploit demo generation
 */
@Slf4j
@Service
public class AIExplanationService {

    @Value("${reachscanner.ai-service.url}")
    private String aiServiceUrl;

    @Value("${reachscanner.ai-service.timeout-seconds:60}")
    private int timeoutSeconds;

    @Value("${reachscanner.ai-service.enabled:true}")
    private boolean enabled;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public AIExplanationService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Generates AI explanations for vulnerabilities with reachability analysis
     * Iteration 4: Now includes exploit demos for EXPLOITABLE vulnerabilities
     *
     * @param vulnerabilities List of vulnerable dependencies to explain
     */
    public void generateExplanations(List<VulnerableDependency> vulnerabilities) {
        if (!enabled) {
            log.info("AI explanation service is disabled. Skipping explanation generation.");
            return;
        }

        log.info("Generating AI explanations for {} vulnerabilities", vulnerabilities.size());

        for (VulnerableDependency vuln : vulnerabilities) {
            // Only generate explanations for vulnerabilities with call chains
            if (vuln.getCallChains() != null && !vuln.getCallChains().isEmpty()) {
                try {
                    generateExplanation(vuln);
                } catch (Exception e) {
                    log.error("Failed to generate explanation for {}: {}",
                            vuln.getCveId(), e.getMessage(), e);
                    // Set default values on failure
                    vuln.setVerdict("NEEDS_REVIEW");
                    vuln.setConfidenceScore(0.0);
                    vuln.setConfidenceReasoning("AI explanation service unavailable");
                    vuln.setPlainEnglishExplanation("Unable to generate explanation at this time.");
                    vuln.setAttackNarrative("Not available");
                    vuln.setExploitDemo(null);
                }
            } else {
                // No call chains - set appropriate defaults
                vuln.setVerdict("NOT_REACHABLE");
                vuln.setConfidenceScore(0.95);
                vuln.setConfidenceReasoning("No reachable paths found in static analysis");
                vuln.setPlainEnglishExplanation(
                        String.format("The vulnerable dependency %s is present in the project, " +
                                        "but our analysis found no reachable code paths from application " +
                                        "entry points to the vulnerable code. This significantly reduces the risk.",
                                vuln.getDependency().toCoordinates())
                );
                vuln.setAttackNarrative("Not applicable - vulnerability is not reachable.");
                vuln.setExploitDemo(null);
            }
        }

        log.info("AI explanation generation completed");
    }

    /**
     * Generates an AI explanation for a single vulnerability
     * Iteration 4: Now extracts exploit demo from response
     */
    private void generateExplanation(VulnerableDependency vuln) throws Exception {
        log.info("Requesting AI explanation for {}", vuln.getCveId());

        // Build request payload
        Map<String, Object> requestBody = buildExplanationRequest(vuln);
        String requestJson = objectMapper.writeValueAsString(requestBody);

        // Make HTTP request to Python service
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(aiServiceUrl + "/api/explain"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .POST(HttpRequest.BodyPublishers.ofString(requestJson))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("AI service returned status " + response.statusCode() +
                    ": " + response.body());
        }

        // Parse response
        parseExplanationResponse(response.body(), vuln);

        log.info("Successfully received AI explanation for {}: verdict={}, confidence={}, hasExploitDemo={}",
                vuln.getCveId(), vuln.getVerdict(), vuln.getConfidenceScore(),
                vuln.getExploitDemo() != null);
    }

    /**
     * Builds the request payload for the AI explanation service
     */
    private Map<String, Object> buildExplanationRequest(VulnerableDependency vuln) {
        Map<String, Object> request = new HashMap<>();

        request.put("cveId", vuln.getCveId());
        request.put("description", vuln.getDescription());
        request.put("severity", vuln.getSeverity());
        request.put("dependencyCoordinates", vuln.getDependency().toCoordinates());

        // Convert call chains to JSON-friendly format
        List<Map<String, Object>> callChains = vuln.getCallChains().stream()
                .map(this::convertCallChain)
                .collect(Collectors.toList());
        request.put("callChains", callChains);

        return request;
    }

    /**
     * Converts a CallChain to a Map for JSON serialization
     */
    private Map<String, Object> convertCallChain(CallChain chain) {
        Map<String, Object> chainMap = new HashMap<>();
        chainMap.put("entryPoint", chain.getEntryPoint());
        chainMap.put("vulnerableSink", chain.getVulnerableSink());
        chainMap.put("isReachable", chain.isReachable());

        List<Map<String, Object>> steps = chain.getSteps().stream()
                .map(this::convertCallStep)
                .collect(Collectors.toList());
        chainMap.put("steps", steps);

        return chainMap;
    }

    /**
     * Converts a CallStep to a Map for JSON serialization
     */
    private Map<String, Object> convertCallStep(CallChain.CallStep step) {
        Map<String, Object> stepMap = new HashMap<>();
        stepMap.put("fileName", step.getFileName());
        stepMap.put("lineNumber", step.getLineNumber());
        stepMap.put("methodName", step.getMethodName());
        stepMap.put("className", step.getClassName());
        stepMap.put("snippet", step.getSnippet());
        return stepMap;
    }

    /**
     * Parses the AI service response and updates the vulnerability object
     * Iteration 4: Now extracts exploit demo if present
     */
    private void parseExplanationResponse(String responseBody, VulnerableDependency vuln) throws Exception {
        JsonNode root = objectMapper.readTree(responseBody);

        // Extract core fields from response
        vuln.setVerdict(root.path("verdict").asText("NEEDS_REVIEW"));
        vuln.setConfidenceScore(root.path("confidenceScore").asDouble(0.5));
        vuln.setConfidenceReasoning(root.path("confidenceReasoning").asText(""));
        vuln.setPlainEnglishExplanation(root.path("plainEnglishExplanation").asText(""));
        vuln.setAttackNarrative(root.path("attackNarrative").asText(""));

        // Iteration 4: Extract exploit demo if present
        if (root.has("exploitDemo") && !root.get("exploitDemo").isNull()) {
            JsonNode exploitNode = root.get("exploitDemo");

            VulnerableDependency.ExploitDemo exploitDemo = VulnerableDependency.ExploitDemo.builder()
                    .attackSetup(exploitNode.path("attackSetup").asText(""))
                    .httpRequest(exploitNode.path("httpRequest").asText(""))
                    .stepByStep(extractStringList(exploitNode.get("stepByStep")))
                    .attackerOutcome(exploitNode.path("attackerOutcome").asText(""))
                    .unsafeCode(exploitNode.path("unsafeCode").asText(""))
                    .safeCode(exploitNode.path("safeCode").asText(""))
                    .build();

            vuln.setExploitDemo(exploitDemo);
            log.debug("Extracted exploit demo for {}", vuln.getCveId());
        } else {
            vuln.setExploitDemo(null);
        }
    }

    /**
     * Helper method to extract a list of strings from a JsonNode array
     */
    private List<String> extractStringList(JsonNode arrayNode) {
        List<String> result = new ArrayList<>();

        if (arrayNode != null && arrayNode.isArray()) {
            for (JsonNode item : arrayNode) {
                result.add(item.asText(""));
            }
        }

        return result;
    }

    /**
     * Checks if the AI service is available
     */
    public boolean isAvailable() {
        if (!enabled) {
            return false;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(aiServiceUrl + "/health"))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;

        } catch (Exception e) {
            log.warn("AI service health check failed: {}", e.getMessage());
            return false;
        }
    }
}