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

    /**
     * Performs a complete vulnerability scan on a repository
     *
     * @param request Scan request containing repository URL
     * @return Scan results with vulnerable dependencies
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

            // Step 4: Build response
            ScanResponse response = ScanResponse.builder()
                    .repoUrl(request.getRepoUrl())
                    .scanTime(LocalDateTime.now())
                    .totalDependencies(dependencies.size())
                    .vulnerableDependencies(vulnerabilities.size())
                    .vulnerabilities(vulnerabilities)
                    .build();

            log.info("Scan completed successfully. Found {} vulnerable dependencies out of {} total dependencies",
                    vulnerabilities.size(), dependencies.size());

            return response;

        } catch (Exception e) {
            log.error("Scan failed for repository {}: {}", request.getRepoUrl(), e.getMessage(), e);
            throw new RuntimeException("Scan failed: " + e.getMessage(), e);
        } finally {
            // Step 5: Clean up - delete cloned repository
            if (repoPath != null) {
                repoCloner.deleteRepository(repoPath);
            }
        }
    }
}