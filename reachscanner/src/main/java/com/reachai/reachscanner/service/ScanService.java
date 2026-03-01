package com.reachai.reachscanner.service;

import com.reachai.reachscanner.dto.ScanRequest;
import com.reachai.reachscanner.dto.ScanResponse;
import com.reachai.reachscanner.model.Dependency;
import com.reachai.reachscanner.model.VulnerableDependency;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanService {

    private final RepoCloner repoCloner;
    private final DependencyScanner dependencyScanner;
    private final CveMatcher cveMatcher;
    private final ReachScanner reachScanner;

    /**
     * Performs a complete vulnerability scan on a repository
     * Iteration 2: Now includes CodeQL reachability analysis
     *
     * @param request Scan request containing repository URL
     * @return Scan results with vulnerable dependencies and call chains
     */
    public ScanResponse performScan(ScanRequest request) {
        log.info("Starting scan for repository: {}", request.getRepoUrl());

        Path repoPath = null;

        try {
            // Step 1: Clone the repository
            repoPath = repoCloner.cloneRepository(request.getRepoUrl());

            // Step 2: Scan for dependencies
            List<Dependency> dependencies = dependencyScanner.scanDependencies(repoPath);

            // Step 3: Match against CVE database
            List<VulnerableDependency> vulnerabilities = cveMatcher.matchCves(dependencies);

            // Step 4: Analyze reachability with CodeQL (NEW in Iteration 2)
            if (!vulnerabilities.isEmpty()) {
                log.info("Found {} vulnerabilities, starting reachability analysis", vulnerabilities.size());
                reachScanner.analyzeReachability(vulnerabilities, repoPath);
            }

            // Step 5: Build response
            ScanResponse response = ScanResponse.builder()
                    .repoUrl(request.getRepoUrl())
                    .scanTime(LocalDateTime.now())
                    .totalDependencies(dependencies.size())
                    .vulnerableDependencies(vulnerabilities.size())
                    .vulnerabilities(vulnerabilities)
                    .build();

            // Log summary
            logScanSummary(vulnerabilities);

            log.info("Scan completed successfully. Found {} vulnerable dependencies out of {} total dependencies",
                    vulnerabilities.size(), dependencies.size());

            return response;

        } catch (Exception e) {
            log.error("Scan failed for repository {}: {}", request.getRepoUrl(), e.getMessage(), e);
            throw new RuntimeException("Scan failed: " + e.getMessage(), e);
        } finally {
            // Step 6: Clean up - delete cloned repository
            if (repoPath != null) {
                repoCloner.deleteRepository(repoPath);
            }
        }
    }

    /**
     * Logs a summary of the scan results including reachability status
     */
    private void logScanSummary(List<VulnerableDependency> vulnerabilities) {
        long reachable = vulnerabilities.stream()
                .filter(v -> Boolean.TRUE.equals(v.getReachable()))
                .count();

        long notReachable = vulnerabilities.stream()
                .filter(v -> Boolean.FALSE.equals(v.getReachable()))
                .count();

        long noQuery = vulnerabilities.stream()
                .filter(v -> "NO_QUERY".equals(v.getReachabilityStatus()))
                .count();

        long analysisFailed = vulnerabilities.stream()
                .filter(v -> "ANALYSIS_FAILED".equals(v.getReachabilityStatus()))
                .count();

        log.info("=== Scan Summary ===");
        log.info("Total vulnerabilities: {}", vulnerabilities.size());
        log.info("  - REACHABLE: {}", reachable);
        log.info("  - NOT_REACHABLE: {}", notReachable);
        log.info("  - NO_QUERY: {}", noQuery);
        log.info("  - ANALYSIS_FAILED: {}", analysisFailed);
    }
}