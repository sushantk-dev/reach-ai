package com.reachai.reachscanner.controller;

import com.reachai.reachscanner.dto.ScanRequest;
import com.reachai.reachscanner.dto.ScanResponse;
import com.reachai.reachscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;

    /**
     * Initiates a vulnerability scan for a GitHub repository
     *
     * @param request Scan request containing repository URL
     * @return Scan results with vulnerable dependencies
     */
    @PostMapping
    public ResponseEntity<ScanResponse> createScan(@Valid @RequestBody ScanRequest request) {
        log.info("Received scan request for repository: {}", request.getRepoUrl());

        try {
            ScanResponse response = scanService.performScan(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error processing scan request: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("ReachScanner is running");
    }
}