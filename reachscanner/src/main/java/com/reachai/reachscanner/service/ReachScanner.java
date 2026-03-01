package com.reachai.reachscanner.service;

import com.reachai.reachscanner.model.CallChain;
import com.reachai.reachscanner.model.VulnerableDependency;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Orchestrates the reachability analysis using CodeQL
 * This service determines if vulnerable dependencies are actually reachable in the codebase
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ReachScanner {

    private final CodeQLRunner codeQLRunner;
    private final CveQueryRegistry cveQueryRegistry;
    private final SarifParser sarifParser;

    /**
     * Analyzes vulnerabilities to determine if they are reachable
     * Updates the VulnerableDependency objects with call chain information
     *
     * @param vulnerabilities List of vulnerable dependencies to analyze
     * @param repoPath Path to the repository being scanned
     */
    public void analyzeReachability(List<VulnerableDependency> vulnerabilities, Path repoPath) {
        log.info("Starting reachability analysis for {} vulnerabilities", vulnerabilities.size());

        // Check if CodeQL is available
        if (!codeQLRunner.isCodeQLAvailable()) {
            log.warn("CodeQL is not available. Skipping reachability analysis.");
            markAllAsNoQuery(vulnerabilities, "CodeQL not available");
            return;
        }

        for (VulnerableDependency vuln : vulnerabilities) {
            try {
                analyzeVulnerability(vuln, repoPath);
            } catch (Exception e) {
                log.error("Error analyzing reachability for {}: {}",
                        vuln.getCveId(), e.getMessage(), e);
                vuln.setReachabilityStatus("ANALYSIS_FAILED");
                vuln.setReachable(null);
                vuln.setCallChains(new ArrayList<>());
            }
        }

        log.info("Reachability analysis completed");
    }

    /**
     * Analyzes a single vulnerability for reachability
     */
    private void analyzeVulnerability(VulnerableDependency vuln, Path repoPath) {
        String cveId = vuln.getCveId();
        log.info("Analyzing reachability for {}", cveId);

        // Check if we have a CodeQL query for this CVE
        Optional<Path> queryPathOpt = cveQueryRegistry.getQueryForCve(cveId);

        if (queryPathOpt.isEmpty()) {
            log.debug("No CodeQL query available for {}", cveId);
            vuln.setReachabilityStatus("NO_QUERY");
            vuln.setReachable(null);
            vuln.setCallChains(new ArrayList<>());
            return;
        }

        Path queryPath = queryPathOpt.get();

        try {
            // Run CodeQL analysis
            Path sarifPath = codeQLRunner.analyzeRepository(repoPath, queryPath);

            // Parse SARIF results
            List<CallChain> callChains = sarifParser.parseCallChains(sarifPath);

            // Update vulnerability with results
            vuln.setCallChains(callChains);

            if (callChains.isEmpty()) {
                log.info("{}: NOT REACHABLE (no call chains found)", cveId);
                vuln.setReachable(false);
                vuln.setReachabilityStatus("NOT_REACHABLE");
            } else {
                log.info("{}: REACHABLE ({} call chain(s) found)", cveId, callChains.size());
                vuln.setReachable(true);
                vuln.setReachabilityStatus("REACHABLE");

                // Log the first call chain for debugging
                if (!callChains.isEmpty()) {
                    CallChain firstChain = callChains.get(0);
                    log.info("  Entry point: {}", firstChain.getEntryPoint());
                    log.info("  Vulnerable sink: {}", firstChain.getVulnerableSink());
                    log.info("  Steps: {}", firstChain.getSteps().size());
                }
            }

            // Clean up SARIF file
            deleteSarifFile(sarifPath);

        } catch (Exception e) {
            log.error("CodeQL analysis failed for {}: {}", cveId, e.getMessage());
            vuln.setReachabilityStatus("ANALYSIS_FAILED");
            vuln.setReachable(null);
            vuln.setCallChains(new ArrayList<>());
        }
    }

    /**
     * Marks all vulnerabilities as having no query available
     */
    private void markAllAsNoQuery(List<VulnerableDependency> vulnerabilities, String reason) {
        for (VulnerableDependency vuln : vulnerabilities) {
            vuln.setReachabilityStatus("NO_QUERY");
            vuln.setReachable(null);
            vuln.setCallChains(new ArrayList<>());
        }
    }

    /**
     * Deletes a SARIF results file
     */
    private void deleteSarifFile(Path sarifPath) {
        try {
            if (sarifPath != null && sarifPath.toFile().exists()) {
                sarifPath.toFile().delete();
                log.debug("Deleted SARIF file: {}", sarifPath);
            }
        } catch (Exception e) {
            log.warn("Failed to delete SARIF file {}: {}", sarifPath, e.getMessage());
        }
    }
}