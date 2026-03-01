package com.reachai.reachscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class CodeQLRunner {

    @Value("${reachscanner.codeql.executable:codeql}")
    private String codeqlExecutable;

    @Value("${reachscanner.codeql.database-dir}")
    private String databaseDir;

    @Value("${reachscanner.codeql.timeout-minutes:30}")
    private int timeoutMinutes;

    /**
     * Creates a CodeQL database for the given repository
     *
     * @param repoPath Path to the repository to analyze
     * @param language Programming language (e.g., "java")
     * @return Path to the created database
     */
    public Path createDatabase(Path repoPath, String language) throws IOException, InterruptedException {
        String dbName = "db_" + System.currentTimeMillis();
        Path dbPath = Paths.get(databaseDir, dbName);

        log.info("Creating CodeQL database at {} for language {}", dbPath, language);

        // Ensure database directory exists
        Files.createDirectories(Paths.get(databaseDir));

        List<String> command = new ArrayList<>();
        command.add(codeqlExecutable);
        command.add("database");
        command.add("create");
        command.add(dbPath.toString());
        command.add("--language=" + language);
        command.add("--source-root=" + repoPath.toString());
        command.add("--overwrite");

        executeCommand(command, "Database creation");

        log.info("Successfully created CodeQL database: {}", dbPath);
        return dbPath;
    }

    /**
     * Runs a CodeQL query against a database and produces SARIF output
     *
     * @param databasePath Path to the CodeQL database
     * @param queryPath Path to the .ql query file
     * @return Path to the generated SARIF results file
     */
    public Path runQuery(Path databasePath, Path queryPath) throws IOException, InterruptedException {
        String resultsFileName = "results_" + System.currentTimeMillis() + ".sarif";
        Path resultsPath = databasePath.getParent().resolve(resultsFileName);

        log.info("Running CodeQL query {} against database {}", queryPath, databasePath);

        List<String> command = new ArrayList<>();
        command.add(codeqlExecutable);
        command.add("database");
        command.add("analyze");
        command.add(databasePath.toString());
        command.add(queryPath.toString());
        command.add("--format=sarif-latest");
        command.add("--output=" + resultsPath.toString());
        command.add("--rerun");

        executeCommand(command, "Query execution");

        if (!Files.exists(resultsPath)) {
            throw new IOException("SARIF results file was not created: " + resultsPath);
        }

        log.info("Successfully generated SARIF results: {}", resultsPath);
        return resultsPath;
    }

    /**
     * Analyzes a repository with CodeQL and returns SARIF results
     * This is a convenience method that combines database creation and query execution
     *
     * @param repoPath Path to the repository
     * @param queryPath Path to the CodeQL query
     * @return Path to the SARIF results file
     */
    public Path analyzeRepository(Path repoPath, Path queryPath) throws IOException, InterruptedException {
        Path databasePath = null;

        try {
            // Create database
            databasePath = createDatabase(repoPath, "java");

            // Run query
            return runQuery(databasePath, queryPath);

        } finally {
            // Clean up database after analysis
            if (databasePath != null) {
                deleteDatabase(databasePath);
            }
        }
    }

    /**
     * Deletes a CodeQL database
     */
    public void deleteDatabase(Path databasePath) {
        try {
            if (Files.exists(databasePath)) {
                log.info("Deleting CodeQL database: {}", databasePath);

                // Use CodeQL CLI to properly delete the database
                List<String> command = new ArrayList<>();
                command.add(codeqlExecutable);
                command.add("database");
                command.add("cleanup");
                command.add(databasePath.toString());
                command.add("--mode=brutal");

                executeCommand(command, "Database deletion");

                // Also delete the directory
                Files.walk(databasePath)
                        .sorted((a, b) -> b.compareTo(a)) // Reverse order for deletion
                        .forEach(path -> {
                            try {
                                Files.deleteIfExists(path);
                            } catch (IOException e) {
                                log.warn("Failed to delete {}: {}", path, e.getMessage());
                            }
                        });

                log.info("Successfully deleted database: {}", databasePath);
            }
        } catch (Exception e) {
            log.error("Error deleting CodeQL database {}: {}", databasePath, e.getMessage());
        }
    }

    /**
     * Executes a CodeQL command and logs output
     */
    private void executeCommand(List<String> command, String operationName) throws IOException, InterruptedException {
        log.debug("Executing command: {}", String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();

        // Capture output
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                log.debug("CodeQL: {}", line);
            }
        }

        // Wait for completion with timeout
        boolean finished = process.waitFor(timeoutMinutes, TimeUnit.MINUTES);

        if (!finished) {
            process.destroyForcibly();
            throw new IOException(operationName + " timed out after " + timeoutMinutes + " minutes");
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            log.error("{} failed with exit code {}", operationName, exitCode);
            log.error("Output: {}", output);
            throw new IOException(operationName + " failed with exit code " + exitCode);
        }

        log.debug("{} completed successfully", operationName);
    }

    /**
     * Checks if CodeQL is available on the system
     */
    public boolean isCodeQLAvailable() {
        try {
            List<String> command = List.of(codeqlExecutable, "version");
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            boolean finished = process.waitFor(5, TimeUnit.SECONDS);

            if (finished && process.exitValue() == 0) {
                log.info("CodeQL is available");
                return true;
            }
        } catch (Exception e) {
            log.warn("CodeQL not available: {}", e.getMessage());
        }

        return false;
    }
}