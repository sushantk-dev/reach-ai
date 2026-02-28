package com.reachai.reachscanner.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VulnerableDependency {
    private Dependency dependency;
    private String cveId;
    private String description;
    private String severity;
}