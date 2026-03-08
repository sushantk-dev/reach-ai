package com.reachai.reachscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class CveQueryRegistry {

    @Value("${reachscanner.codeql.queries-dir:./queries}")
    private String queriesDir;

    /**
     * Maps CVE IDs to their underlying CWE (Common Weakness Enumeration) pattern.
     *
     * IMPORTANT: CodeQL does NOT detect CVEs directly. It detects vulnerability PATTERNS.
     * Multiple CVEs can map to the same CWE pattern.
     */
    private static final Map<String, CwePattern> CVE_TO_CWE = new HashMap<>();

    /**
     * Maps CWE patterns to CodeQL queries that detect them
     */
    private static final Map<String, QueryInfo> CWE_TO_QUERY = new HashMap<>();

    static {
        // Define built-in CodeQL queries for each CWE pattern
        CWE_TO_QUERY.put("CWE-502", new QueryInfo(
                "codeql/java-queries:Security/CWE/CWE-502/UnsafeDeserialization.ql",
                "Unsafe Deserialization",
                "Detects taint flow from user input to deserialization sinks",
                true
        ));

        CWE_TO_QUERY.put("CWE-074", new QueryInfo(
                "codeql/java-queries:Security/CWE/CWE-074/JndiInjection.ql",
                "JNDI Injection",
                "Detects JNDI lookup with user-controlled data",
                true
        ));

        CWE_TO_QUERY.put("CWE-094", new QueryInfo(
                "codeql/java-queries:Security/CWE/CWE-094/BeanValidation.ql",
                "Code Injection",
                "Detects dynamic code execution with user input",
                true
        ));

        CWE_TO_QUERY.put("CWE-078", new QueryInfo(
                "codeql/java-queries:Security/CWE/CWE-078/ExecTainted.ql",
                "Command Injection",
                "Detects OS command execution with user input",
                true
        ));

        // Map CVEs to their CWE patterns with vulnerable class/method info

        // Jackson Databind vulnerabilities (unsafe deserialization)
        CVE_TO_CWE.put("CVE-2019-14379", new CwePattern(
                "CWE-502",
                "com.fasterxml.jackson.databind.ObjectMapper",
                Arrays.asList("readValue", "readTree", "treeToValue")
        ));

        CVE_TO_CWE.put("CVE-2020-8840", new CwePattern(
                "CWE-502",
                "com.fasterxml.jackson.databind.ObjectMapper",
                Arrays.asList("readValue", "readTree")
        ));

        // Log4j (JNDI injection)
        CVE_TO_CWE.put("CVE-2021-44228", new CwePattern(
                "CWE-074",
                "org.apache.logging.log4j.Logger",
                Arrays.asList("info", "warn", "error", "debug", "trace", "fatal")
        ));

        // Struts (command injection / OGNL injection)
        CVE_TO_CWE.put("CVE-2017-5638", new CwePattern(
                "CWE-094",
                "org.apache.struts2",
                Collections.emptyList()
        ));

        // Spring Framework vulnerabilities
        CVE_TO_CWE.put("CVE-2022-22965", new CwePattern(
                "CWE-094",
                "org.springframework.beans",
                Collections.emptyList()
        ));

        CVE_TO_CWE.put("CVE-2018-1270", new CwePattern(
                "CWE-094",
                "org.springframework.messaging.simp",
                Collections.emptyList()
        ));
    }

    /**
     * Gets the CodeQL query for a given CVE
     *
     * This method:
     * 1. Maps the CVE to its CWE pattern
     * 2. Returns the query that detects that pattern
     * 3. The query results will be filtered by the vulnerable library in ReachScanner
     */
    public Optional<QueryInfo> getQueryForCve(String cveId) {
        CwePattern cwePattern = CVE_TO_CWE.get(cveId);

        if (cwePattern == null) {
            log.debug("No CWE mapping found for CVE: {}", cveId);
            return Optional.empty();
        }

        QueryInfo queryInfo = CWE_TO_QUERY.get(cwePattern.getCweId());

        if (queryInfo == null) {
            log.warn("CWE {} mapped for CVE {} but no query defined",
                    cwePattern.getCweId(), cveId);
            return Optional.empty();
        }

        log.debug("CVE {} → {} → Query: {}",
                cveId, cwePattern.getCweId(), queryInfo.getQueryPath());

        return Optional.of(queryInfo);
    }

    /**
     * Gets the CWE pattern for a CVE (used for additional validation)
     */
    public Optional<CwePattern> getCwePatternForCve(String cveId) {
        return Optional.ofNullable(CVE_TO_CWE.get(cveId));
    }

    /**
     * Checks if a CodeQL query exists for the given CVE
     */
    public boolean hasQueryForCve(String cveId) {
        return CVE_TO_CWE.containsKey(cveId) &&
                CWE_TO_QUERY.containsKey(CVE_TO_CWE.get(cveId).getCweId());
    }

    /**
     * Gets all supported CVEs (those with CodeQL queries)
     */
    public Map<String, String> getAllSupportedCves() {
        Map<String, String> result = new HashMap<>();

        CVE_TO_CWE.forEach((cveId, cwePattern) -> {
            QueryInfo queryInfo = CWE_TO_QUERY.get(cwePattern.getCweId());
            if (queryInfo != null) {
                result.put(cveId, queryInfo.getQueryPath());
            }
        });

        return result;
    }

    /**
     * Represents a CWE pattern with the vulnerable class/methods
     */
    public static class CwePattern {
        private final String cweId;
        private final String vulnerableClass;
        private final List<String> vulnerableMethods;

        public CwePattern(String cweId, String vulnerableClass, List<String> vulnerableMethods) {
            this.cweId = cweId;
            this.vulnerableClass = vulnerableClass;
            this.vulnerableMethods = vulnerableMethods;
        }

        public String getCweId() { return cweId; }
        public String getVulnerableClass() { return vulnerableClass; }
        public List<String> getVulnerableMethods() { return vulnerableMethods; }
    }

    /**
     * Information about a CodeQL query
     *
     * IMPORTANT: queryPath is a String that CodeQL CLI interprets directly.
     * It can be:
     * - A file path: "queries/MyQuery.ql"
     * - A built-in query: "codeql/java-queries:Security/CWE/CWE-502/UnsafeDeserialization.ql"
     *
     * DO NOT convert to Path object on Windows - the colon in built-in queries causes InvalidPathException
     */
    public static class QueryInfo {
        private final String queryPath;
        private final String name;
        private final String description;
        private final boolean isBuiltIn;

        public QueryInfo(String queryPath, String name, String description, boolean isBuiltIn) {
            this.queryPath = queryPath;
            this.name = name;
            this.description = description;
            this.isBuiltIn = isBuiltIn;
        }

        public String getQueryPath() { return queryPath; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public boolean isBuiltIn() { return isBuiltIn; }
    }
}