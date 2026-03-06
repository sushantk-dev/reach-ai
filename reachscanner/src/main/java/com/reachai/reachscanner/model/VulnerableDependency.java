package com.reachai.reachscanner.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VulnerableDependency {
    // Core dependency info
    private Dependency dependency;
    private String cveId;
    private String description;
    private String severity;

    // Iteration 2: Reachability analysis
    private Boolean reachable;
    private String reachabilityStatus;
    private List<CallChain> callChains;

    // Iteration 3: AI explanation
    private String verdict;
    private Double confidenceScore;
    private String confidenceReasoning;
    private String plainEnglishExplanation;
    private String attackNarrative;

    // Iteration 4: Exploit demo (only present when verdict is EXPLOITABLE)
    private ExploitDemo exploitDemo;

    /**
     * Iteration 4: Exploit demonstration details
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExploitDemo {
        private String attackSetup;
        private String httpRequest;
        private List<String> stepByStep;
        private String attackerOutcome;
        private String unsafeCode;
        private String safeCode;
    }
}