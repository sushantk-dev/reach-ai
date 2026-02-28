package com.reachai.reachscanner.dto;

import com.reachai.reachscanner.model.VulnerableDependency;

import java.time.LocalDateTime;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanResponse {
    private String repoUrl;
    private LocalDateTime scanTime;
    private int totalDependencies;
    private int vulnerableDependencies;
    private List<VulnerableDependency> vulnerabilities;
}
