package com.reachai.reachscanner.controller;

import com.reachai.reachscanner.service.CodeQLRunner;
import com.reachai.reachscanner.service.CveQueryRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Test endpoints for verifying CodeQL integration
 */
@Slf4j
@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class TestController {

    private final CodeQLRunner codeQLRunner;
    private final CveQueryRegistry cveQueryRegistry;

    /**
     * Check if CodeQL is properly configured
     */
    @GetMapping("/codeql-status")
    public ResponseEntity<Map<String, Object>> checkCodeQLStatus() {
        Map<String, Object> status = new HashMap<>();

        boolean available = codeQLRunner.isCodeQLAvailable();
        status.put("codeqlAvailable", available);
        status.put("supportedCves", cveQueryRegistry.getAllSupportedCves());

        if (available) {
            status.put("message", "CodeQL is properly configured");
        } else {
            status.put("message", "CodeQL CLI not found. Please install CodeQL and add it to PATH");
            status.put("installGuide", "https://github.com/github/codeql-cli-binaries/releases");
        }

        return ResponseEntity.ok(status);
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("Test controller is running");
    }
}