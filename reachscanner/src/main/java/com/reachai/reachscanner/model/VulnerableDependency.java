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
    private Dependency dependency;
    private String cveId;
    private String description;
    private String severity;

    // CodeQL reachability analysis results (Iteration 2)
    private List<CallChain> callChains;
    private Boolean reachable;
    private String reachabilityStatus; // "REACHABLE", "NOT_REACHABLE", "ANALYSIS_FAILED", "NO_QUERY"
}