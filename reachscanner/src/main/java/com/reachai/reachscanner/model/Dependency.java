package com.reachai.reachscanner.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Dependency {
    private String groupId;
    private String artifactId;
    private String version;

    public String toCoordinates() {
        return String.format("%s:%s:%s", groupId, artifactId, version);
    }
}