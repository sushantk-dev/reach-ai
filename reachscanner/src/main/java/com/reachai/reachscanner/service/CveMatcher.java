package com.reachai.reachscanner.service;

import com.reachai.reachscanner.data.KnownCve;
import com.reachai.reachscanner.model.Dependency;
import com.reachai.reachscanner.model.VulnerableDependency;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class CveMatcher {

    /**
     * Matches dependencies against known CVE database
     *
     * @param dependencies List of dependencies to check
     * @return List of vulnerable dependencies with CVE information
     */
    public List<VulnerableDependency> matchCves(List<Dependency> dependencies) {
        log.info("Matching {} dependencies against CVE database", dependencies.size());

        List<VulnerableDependency> vulnerabilities = new ArrayList<>();

        for (Dependency dependency : dependencies) {
            List<KnownCve> matchingCves = findMatchingCves(dependency);

            for (KnownCve cve : matchingCves) {
                VulnerableDependency vuln = VulnerableDependency.builder()
                        .dependency(dependency)
                        .cveId(cve.getCveId())
                        .description(cve.getDescription())
                        .severity(cve.getSeverity())
                        .build();

                vulnerabilities.add(vuln);
                log.info("Found vulnerability: {} in {}:{} version {}",
                        cve.getCveId(),
                        dependency.getGroupId(),
                        dependency.getArtifactId(),
                        dependency.getVersion());
            }
        }

        log.info("Total vulnerabilities found: {}", vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Finds all CVEs that match a given dependency
     */
    private List<KnownCve> findMatchingCves(Dependency dependency) {
        List<KnownCve> matches = new ArrayList<>();

        for (KnownCve cve : KnownCve.CveDatabase.TOP_10_JAVA_CVES) {
            if (isMatch(dependency, cve)) {
                matches.add(cve);
            }
        }

        return matches;
    }

    /**
     * Checks if a dependency matches a CVE based on groupId, artifactId, and version
     */
    private boolean isMatch(Dependency dependency, KnownCve cve) {
        // Check groupId and artifactId
        if (!cve.getGroupId().equals(dependency.getGroupId())) {
            return false;
        }
        if (!cve.getArtifactId().equals(dependency.getArtifactId())) {
            return false;
        }

        // Check if version is in the vulnerable versions list
        String depVersion = normalizeVersion(dependency.getVersion());

        for (String vulnerableVersion : cve.getVulnerableVersions()) {
            String normalizedVulnVersion = normalizeVersion(vulnerableVersion);
            if (depVersion.equals(normalizedVulnVersion)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalizes version strings for comparison
     * Removes .RELEASE suffix and other common Maven suffixes
     */
    private String normalizeVersion(String version) {
        if (version == null) {
            return "";
        }

        return version
                .replace(".RELEASE", "")
                .replace("-RELEASE", "")
                .trim();
    }
}