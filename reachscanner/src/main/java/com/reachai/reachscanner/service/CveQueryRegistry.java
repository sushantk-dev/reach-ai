package com.reachai.reachscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class CveQueryRegistry {

    @Value("${reachscanner.codeql.queries-dir}")
    private String queriesDir;

    // Maps CVE IDs to their corresponding CodeQL query files
    private static final Map<String, String> CVE_TO_QUERY = new HashMap<>();

    static {
        // Jackson Databind unsafe deserialization
        CVE_TO_QUERY.put("CVE-2019-14379", "JacksonUnsafeDeserialization.ql");
        CVE_TO_QUERY.put("CVE-2020-8840", "JacksonUnsafeDeserialization.ql");

        // Log4j RCE
        CVE_TO_QUERY.put("CVE-2021-44228", "Log4jJndiLookup.ql");

        // Spring Framework vulnerabilities
        CVE_TO_QUERY.put("CVE-2022-22965", "SpringBeanPropertyBinding.ql");
        CVE_TO_QUERY.put("CVE-2018-1270", "SpringWebSocketStomp.ql");

        // Struts RCE
        CVE_TO_QUERY.put("CVE-2017-5638", "StrutsContentType.ql");
    }

    /**
     * Gets the CodeQL query file path for a given CVE
     *
     * @param cveId The CVE identifier
     * @return Optional containing the path to the query file, or empty if no query exists
     */
    public Optional<Path> getQueryForCve(String cveId) {
        String queryFileName = CVE_TO_QUERY.get(cveId);

        if (queryFileName == null) {
            log.debug("No CodeQL query registered for CVE: {}", cveId);
            return Optional.empty();
        }

        Path queryPath = Paths.get(queriesDir, queryFileName);
        log.debug("Found CodeQL query for {}: {}", cveId, queryPath);

        return Optional.of(queryPath);
    }

    /**
     * Checks if a CodeQL query exists for the given CVE
     */
    public boolean hasQueryForCve(String cveId) {
        return CVE_TO_QUERY.containsKey(cveId);
    }

    /**
     * Gets all supported CVEs (those with CodeQL queries)
     */
    public Map<String, String> getAllSupportedCves() {
        return new HashMap<>(CVE_TO_QUERY);
    }
}