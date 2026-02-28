package com.reachai.reachscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

@Slf4j
@Service
public class RepoCloner {

    @Value("${reachscanner.clone.base-dir}")
    private String baseDir;

    /**
     * Clones a GitHub repository to a temporary local directory
     *
     * @param repoUrl GitHub repository URL
     * @return Path to the cloned repository
     * @throws GitAPIException if git clone fails
     */
    public Path cloneRepository(String repoUrl) throws GitAPIException, IOException {
        // Create base directory if it doesn't exist
        Path basePath = Path.of(baseDir);
        if (!Files.exists(basePath)) {
            Files.createDirectories(basePath);
        }

        // Extract repo name from URL
        String repoName = extractRepoName(repoUrl);

        // Create unique directory with timestamp
        String dirName = repoName + "_" + System.currentTimeMillis();
        Path clonePath = basePath.resolve(dirName);

        log.info("Cloning repository {} to {}", repoUrl, clonePath);

        try {
            Git.cloneRepository()
                    .setURI(repoUrl)
                    .setDirectory(clonePath.toFile())
                    .setDepth(1) // Shallow clone for faster performance
                    .call()
                    .close();

            log.info("Successfully cloned repository to {}", clonePath);
            return clonePath;
        } catch (GitAPIException e) {
            log.error("Failed to clone repository {}: {}", repoUrl, e.getMessage());
            // Clean up partial clone if it exists
            deleteDirectory(clonePath);
            throw e;
        }
    }

    /**
     * Deletes a cloned repository directory
     *
     * @param repoPath Path to the repository to delete
     */
    public void deleteRepository(Path repoPath) {
        try {
            deleteDirectory(repoPath);
            log.info("Deleted repository directory: {}", repoPath);
        } catch (IOException e) {
            log.error("Failed to delete repository directory {}: {}", repoPath, e.getMessage());
        }
    }

    /**
     * Extracts the repository name from a GitHub URL
     * Example: https://github.com/user/repo.git -> repo
     */
    private String extractRepoName(String repoUrl) {
        String cleaned = repoUrl.replace(".git", "");
        String[] parts = cleaned.split("/");
        return parts[parts.length - 1];
    }

    /**
     * Recursively deletes a directory and all its contents
     */
    private void deleteDirectory(Path path) throws IOException {
        if (Files.exists(path)) {
            Files.walk(path)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }
}