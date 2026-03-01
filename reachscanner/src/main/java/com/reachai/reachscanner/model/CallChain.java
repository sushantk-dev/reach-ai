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
public class CallChain {
    private String entryPoint;
    private String vulnerableSink;
    private List<CallStep> steps;
    private boolean isReachable;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CallStep {
        private String fileName;
        private int lineNumber;
        private String methodName;
        private String className;
        private String snippet;
    }
}