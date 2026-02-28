package com.reachai.reachscanner.service;

import com.reachai.reachscanner.model.Dependency;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.springframework.stereotype.Service;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Service
public class DependencyScanner {

    /**
     * Scans a repository for Maven dependencies by parsing pom.xml files
     *
     * @param repoPath Path to the cloned repository
     * @return List of dependencies found in the repository
     */
    public List<Dependency> scanDependencies(Path repoPath) throws IOException {
        log.info("Scanning dependencies in {}", repoPath);

        List<Dependency> allDependencies = new ArrayList<>();

        // Find all pom.xml files in the repository
        List<Path> pomFiles = findPomFiles(repoPath);

        if (pomFiles.isEmpty()) {
            log.warn("No pom.xml files found in repository");
            return allDependencies;
        }

        log.info("Found {} pom.xml file(s)", pomFiles.size());

        // Parse each pom.xml file
        for (Path pomFile : pomFiles) {
            try {
                List<Dependency> dependencies = parsePomFile(pomFile);
                allDependencies.addAll(dependencies);
                log.info("Extracted {} dependencies from {}", dependencies.size(), pomFile.getFileName());
            } catch (Exception e) {
                log.error("Failed to parse {}: {}", pomFile, e.getMessage());
            }
        }

        // Remove duplicates based on groupId:artifactId:version
        List<Dependency> uniqueDependencies = allDependencies.stream()
                .distinct()
                .collect(Collectors.toList());

        log.info("Total unique dependencies found: {}", uniqueDependencies.size());
        return uniqueDependencies;
    }

    /**
     * Finds all pom.xml files in the repository
     */
    private List<Path> findPomFiles(Path repoPath) throws IOException {
        try (Stream<Path> paths = Files.walk(repoPath)) {
            return paths
                    .filter(path -> path.getFileName().toString().equals("pom.xml"))
                    .filter(path -> !path.toString().contains("target")) // Skip build directories
                    .collect(Collectors.toList());
        }
    }

    /**
     * Parses a pom.xml file and extracts dependencies
     */
    private List<Dependency> parsePomFile(Path pomFile) throws IOException, XmlPullParserException {
        List<Dependency> dependencies = new ArrayList<>();

        MavenXpp3Reader reader = new MavenXpp3Reader();
        Model model;

        try (FileReader fileReader = new FileReader(pomFile.toFile())) {
            model = reader.read(fileReader);
        }

        // Extract dependencies
        if (model.getDependencies() != null) {
            for (org.apache.maven.model.Dependency dep : model.getDependencies()) {
                // Skip test dependencies
                if ("test".equals(dep.getScope())) {
                    continue;
                }

                Dependency dependency = Dependency.builder()
                        .groupId(dep.getGroupId())
                        .artifactId(dep.getArtifactId())
                        .version(resolveVersion(dep.getVersion(), model))
                        .build();

                dependencies.add(dependency);
            }
        }

        // Extract dependencies from dependencyManagement (if present)
        if (model.getDependencyManagement() != null &&
                model.getDependencyManagement().getDependencies() != null) {
            for (org.apache.maven.model.Dependency dep : model.getDependencyManagement().getDependencies()) {
                Dependency dependency = Dependency.builder()
                        .groupId(dep.getGroupId())
                        .artifactId(dep.getArtifactId())
                        .version(resolveVersion(dep.getVersion(), model))
                        .build();

                dependencies.add(dependency);
            }
        }

        return dependencies;
    }

    /**
     * Resolves Maven property placeholders in version strings
     * Example: ${jackson.version} -> 2.9.8
     */
    private String resolveVersion(String version, Model model) {
        if (version == null) {
            return "unknown";
        }

        // If version is a property reference, try to resolve it
        if (version.startsWith("${") && version.endsWith("}")) {
            String propertyName = version.substring(2, version.length() - 1);

            // Try to get from properties
            if (model.getProperties() != null) {
                String resolvedVersion = model.getProperties().getProperty(propertyName);
                if (resolvedVersion != null) {
                    return resolvedVersion;
                }
            }

            // Try special properties
            if ("project.version".equals(propertyName) && model.getVersion() != null) {
                return model.getVersion();
            }
            if ("project.parent.version".equals(propertyName) && model.getParent() != null) {
                return model.getParent().getVersion();
            }

            // If we can't resolve it, return as-is
            return version;
        }

        return version;
    }
}