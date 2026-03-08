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
 *
 * IMPORTANT: CodeQL detects vulnerability PATTERNS (CWE), not specific CVEs.
 * This service:
 * 1. Maps CVE → CWE pattern
 * 2. Runs CodeQL query for that pattern
 * 3. Validates that results actually use the vulnerable library version
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

        // Step 1: Get the CodeQL query for this CVE's pattern
        Optional<CveQueryRegistry.QueryInfo> queryInfoOpt = cveQueryRegistry.getQueryForCve(cveId);

        if (queryInfoOpt.isEmpty()) {
            log.debug("No CodeQL query available for {}", cveId);
            vuln.setReachabilityStatus("NO_QUERY");
            vuln.setReachable(null);
            vuln.setCallChains(new ArrayList<>());
            return;
        }

        CveQueryRegistry.QueryInfo queryInfo = queryInfoOpt.get();

        // IMPORTANT: Pass query as String, not Path
        // Built-in queries like "codeql/java-queries:..." can't be converted to Windows paths
        String queryString = queryInfo.getQueryPath();

        // Step 2: Get the CWE pattern to validate results
        Optional<CveQueryRegistry.CwePattern> cwePatternOpt =
                cveQueryRegistry.getCwePatternForCve(cveId);

        try {
            // Step 3: Run CodeQL analysis with query string
            log.info("Running CodeQL query: {} for {}", queryInfo.getName(), cveId);
            Path sarifPath = codeQLRunner.analyzeRepository(repoPath, queryString);

            // Step 4: Parse SARIF results
            List<CallChain> allCallChains = sarifParser.parseCallChains(sarifPath);

            // Step 5: Filter call chains to only include those using the vulnerable library
            List<CallChain> relevantCallChains = filterRelevantCallChains(
                    allCallChains,
                    vuln,
                    cwePatternOpt
            );

            // Step 6: Update vulnerability with results
            vuln.setCallChains(relevantCallChains);

            if (relevantCallChains.isEmpty()) {
                if (allCallChains.isEmpty()) {
                    log.info("{}: NOT REACHABLE (no vulnerability pattern found)", cveId);
                } else {
                    log.info("{}: NOT REACHABLE (pattern found but doesn't use vulnerable library)", cveId);
                    log.debug("  Found {} call chains but none match {}",
                            allCallChains.size(), vuln.getDependency().toCoordinates());
                }
                vuln.setReachable(false);
                vuln.setReachabilityStatus("NOT_REACHABLE");
            } else {
                log.info("{}: REACHABLE ({} call chain(s) found)", cveId, relevantCallChains.size());
                vuln.setReachable(true);
                vuln.setReachabilityStatus("REACHABLE");

                // Log the first call chain for debugging
                CallChain firstChain = relevantCallChains.get(0);
                log.info("  Entry point: {}", firstChain.getEntryPoint());
                log.info("  Vulnerable sink: {}", firstChain.getVulnerableSink());
                log.info("  Steps: {}", firstChain.getSteps().size());
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
     * Filters call chains to only include those that actually use the vulnerable library
     *
     * This is CRITICAL because:
     * - CodeQL detects the PATTERN (e.g., "unsafe deserialization")
     * - But the app might use a SAFE version of the library
     * - We need to verify the call chain uses the VULNERABLE dependency
     */
    private List<CallChain> filterRelevantCallChains(
            List<CallChain> allCallChains,
            VulnerableDependency vuln,
            Optional<CveQueryRegistry.CwePattern> cwePatternOpt) {

        if (allCallChains.isEmpty()) {
            return new ArrayList<>();
        }

        // If no CWE pattern specified, return all chains (can't filter)
        if (cwePatternOpt.isEmpty()) {
            log.debug("No CWE pattern for filtering, returning all {} chains", allCallChains.size());
            return allCallChains;
        }

        CveQueryRegistry.CwePattern pattern = cwePatternOpt.get();
        List<CallChain> filtered = new ArrayList<>();

        for (CallChain chain : allCallChains) {
            if (callChainUsesVulnerableLibrary(chain, pattern, vuln)) {
                filtered.add(chain);
            }
        }

        log.debug("Filtered {} call chains to {} relevant ones",
                allCallChains.size(), filtered.size());

        return filtered;
    }

    /**
     * Checks if a call chain actually uses the vulnerable library/class
     */
    private boolean callChainUsesVulnerableLibrary(
            CallChain chain,
            CveQueryRegistry.CwePattern pattern,
            VulnerableDependency vuln) {

        String vulnerableClass = pattern.getVulnerableClass();
        List<String> vulnerableMethods = pattern.getVulnerableMethods();

        // Extract just the class name from the fully qualified class
        // e.g., "com.fasterxml.jackson.databind.ObjectMapper" -> "ObjectMapper"
        String simpleClassName = vulnerableClass.substring(vulnerableClass.lastIndexOf('.') + 1);

        // Check if any step in the chain uses the vulnerable class
        for (CallChain.CallStep step : chain.getSteps()) {
            // Check class name (e.g., "ObjectMapper")
            if (step.getClassName() != null) {
                if (step.getClassName().equals(simpleClassName) ||
                        step.getClassName().contains(simpleClassName)) {

                    // If no specific methods specified, class match is enough
                    if (vulnerableMethods.isEmpty()) {
                        log.debug("Call chain uses vulnerable class: {}", vulnerableClass);
                        return true;
                    }

                    // Check if method matches
                    for (String vulnMethod : vulnerableMethods) {
                        if (step.getMethodName() != null &&
                                step.getMethodName().contains(vulnMethod)) {
                            log.debug("Call chain uses vulnerable method: {}.{}",
                                    simpleClassName, vulnMethod);
                            return true;
                        }
                    }
                }
            }

            // Also check in code snippet
            if (step.getSnippet() != null) {
                // Check if snippet contains the class name
                if (step.getSnippet().contains(simpleClassName)) {
                    // Check for methods
                    for (String vulnMethod : vulnerableMethods) {
                        if (step.getSnippet().contains(vulnMethod)) {
                            log.debug("Call chain snippet contains vulnerable method: {}", vulnMethod);
                            return true;
                        }
                    }

                    // If no methods specified, class in snippet is enough
                    if (vulnerableMethods.isEmpty()) {
                        log.debug("Call chain snippet contains vulnerable class: {}", simpleClassName);
                        return true;
                    }
                }
            }
        }

        log.debug("Call chain does not use vulnerable library {}", vulnerableClass);
        return false;
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