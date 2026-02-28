package com.reachai.reachscanner.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KnownCve {
    private String cveId;
    private String groupId;
    private String artifactId;
    private List<String> vulnerableVersions;
    private String description;
    private String severity;

    public static class CveDatabase {
        public static final List<KnownCve> TOP_10_JAVA_CVES = Arrays.asList(
                // CVE-2019-14379 - Jackson Databind - SubTypeValidator
                KnownCve.builder()
                        .cveId("CVE-2019-14379")
                        .groupId("com.fasterxml.jackson.core")
                        .artifactId("jackson-databind")
                        .vulnerableVersions(Arrays.asList(
                                "2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0",
                                "2.7.0", "2.7.1", "2.7.2", "2.7.3", "2.7.4", "2.7.5", "2.7.6", "2.7.7", "2.7.8", "2.7.9",
                                "2.8.0", "2.8.1", "2.8.2", "2.8.3", "2.8.4", "2.8.5", "2.8.6", "2.8.7", "2.8.8", "2.8.9", "2.8.10", "2.8.11",
                                "2.9.0", "2.9.1", "2.9.2", "2.9.3", "2.9.4", "2.9.5", "2.9.6", "2.9.7", "2.9.8", "2.9.9"
                        ))
                        .description("FasterXML jackson-databind 2.x before 2.9.9.2 might allow attackers to have unspecified impact by leveraging failure to block the logback-core class from polymorphic deserialization.")
                        .severity("CRITICAL")
                        .build(),

                // CVE-2017-5638 - Apache Struts 2 - Remote Code Execution
                KnownCve.builder()
                        .cveId("CVE-2017-5638")
                        .groupId("org.apache.struts")
                        .artifactId("struts2-core")
                        .vulnerableVersions(Arrays.asList(
                                "2.3.5", "2.3.6", "2.3.7", "2.3.8", "2.3.9", "2.3.10", "2.3.11", "2.3.12",
                                "2.3.13", "2.3.14", "2.3.15", "2.3.16", "2.3.17", "2.3.18", "2.3.19", "2.3.20",
                                "2.3.21", "2.3.22", "2.3.23", "2.3.24", "2.3.25", "2.3.26", "2.3.27", "2.3.28",
                                "2.3.29", "2.3.30", "2.3.31", "2.5", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5",
                                "2.5.6", "2.5.7", "2.5.8", "2.5.9", "2.5.10"
                        ))
                        .description("The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header.")
                        .severity("CRITICAL")
                        .build(),

                // CVE-2021-44228 - Log4j - Remote Code Execution
                KnownCve.builder()
                        .cveId("CVE-2021-44228")
                        .groupId("org.apache.logging.log4j")
                        .artifactId("log4j-core")
                        .vulnerableVersions(Arrays.asList(
                                "2.0", "2.0.1", "2.0.2", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.6.1", "2.6.2",
                                "2.7", "2.8", "2.8.1", "2.8.2", "2.9.0", "2.9.1", "2.10.0", "2.11.0", "2.11.1", "2.11.2",
                                "2.12.0", "2.12.1", "2.13.0", "2.13.1", "2.13.2", "2.13.3", "2.14.0", "2.14.1"
                        ))
                        .description("Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.")
                        .severity("CRITICAL")
                        .build(),

                // CVE-2022-22965 - Spring Framework - Spring4Shell
                KnownCve.builder()
                        .cveId("CVE-2022-22965")
                        .groupId("org.springframework")
                        .artifactId("spring-beans")
                        .vulnerableVersions(Arrays.asList(
                                "5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "5.3.6", "5.3.7", "5.3.8",
                                "5.3.9", "5.3.10", "5.3.11", "5.3.12", "5.3.13", "5.3.14", "5.3.15", "5.3.16", "5.3.17"
                        ))
                        .description("A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment.")
                        .severity("CRITICAL")
                        .build(),

                // CVE-2018-1270 - Spring Framework - Remote Code Execution
                KnownCve.builder()
                        .cveId("CVE-2018-1270")
                        .groupId("org.springframework")
                        .artifactId("spring-messaging")
                        .vulnerableVersions(Arrays.asList(
                                "5.0.0.RELEASE", "5.0.1.RELEASE", "5.0.2.RELEASE", "5.0.3.RELEASE", "5.0.4.RELEASE",
                                "4.3.0.RELEASE", "4.3.1.RELEASE", "4.3.2.RELEASE", "4.3.3.RELEASE", "4.3.4.RELEASE",
                                "4.3.5.RELEASE", "4.3.6.RELEASE", "4.3.7.RELEASE", "4.3.8.RELEASE", "4.3.9.RELEASE",
                                "4.3.10.RELEASE", "4.3.11.RELEASE", "4.3.12.RELEASE", "4.3.13.RELEASE", "4.3.14.RELEASE"
                        ))
                        .description("Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module.")
                        .severity("HIGH")
                        .build(),

                // CVE-2020-5398 - Spring Framework - Directory Traversal
                KnownCve.builder()
                        .cveId("CVE-2020-5398")
                        .groupId("org.springframework")
                        .artifactId("spring-webmvc")
                        .vulnerableVersions(Arrays.asList(
                                "5.2.0.RELEASE", "5.2.1.RELEASE", "5.2.2.RELEASE", "5.2.3.RELEASE",
                                "5.1.0.RELEASE", "5.1.1.RELEASE", "5.1.2.RELEASE", "5.1.3.RELEASE", "5.1.4.RELEASE",
                                "5.1.5.RELEASE", "5.1.6.RELEASE", "5.1.7.RELEASE", "5.1.8.RELEASE", "5.1.9.RELEASE",
                                "5.1.10.RELEASE", "5.1.11.RELEASE", "5.1.12.RELEASE", "5.1.13.RELEASE"
                        ))
                        .description("In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected file download (RFD) attack when it sets a 'Content-Disposition' header in the response.")
                        .severity("MEDIUM")
                        .build(),

                // CVE-2016-1000027 - Spring Framework - Information Disclosure
                KnownCve.builder()
                        .cveId("CVE-2016-1000027")
                        .groupId("org.springframework")
                        .artifactId("spring-web")
                        .vulnerableVersions(Arrays.asList(
                                "3.0.0.RELEASE", "3.0.1.RELEASE", "3.0.2.RELEASE", "3.0.3.RELEASE", "3.0.4.RELEASE", "3.0.5.RELEASE",
                                "3.1.0.RELEASE", "3.1.1.RELEASE", "3.1.2.RELEASE", "3.1.3.RELEASE", "3.1.4.RELEASE",
                                "3.2.0.RELEASE", "3.2.1.RELEASE", "3.2.2.RELEASE", "3.2.3.RELEASE", "3.2.4.RELEASE"
                        ))
                        .description("The Spring Framework 3.0.x before 3.2.18, 4.1.x before 4.1.9, and 4.2.x before 4.2.4 does not consider URL path parameters when processing security constraints.")
                        .severity("HIGH")
                        .build(),

                // CVE-2019-11272 - Spring Security - Authorization Bypass
                KnownCve.builder()
                        .cveId("CVE-2019-11272")
                        .groupId("org.springframework.security")
                        .artifactId("spring-security-core")
                        .vulnerableVersions(Arrays.asList(
                                "5.1.0.RELEASE", "5.1.1.RELEASE", "5.1.2.RELEASE", "5.1.3.RELEASE", "5.1.4.RELEASE",
                                "5.0.0.RELEASE", "5.0.1.RELEASE", "5.0.2.RELEASE", "5.0.3.RELEASE", "5.0.4.RELEASE",
                                "5.0.5.RELEASE", "5.0.6.RELEASE", "5.0.7.RELEASE", "5.0.8.RELEASE"
                        ))
                        .description("Spring Security, versions 5.1.x prior to 5.1.5, and 5.0.x prior to 5.0.12, and older unsupported versions support plain text passwords using the prefix {noop}.")
                        .severity("HIGH")
                        .build(),

                // CVE-2020-13956 - Apache HttpClient - Man-in-the-Middle
                KnownCve.builder()
                        .cveId("CVE-2020-13956")
                        .groupId("org.apache.httpcomponents")
                        .artifactId("httpclient")
                        .vulnerableVersions(Arrays.asList(
                                "4.0", "4.0.1", "4.0.2", "4.0.3",
                                "4.1", "4.1.1", "4.1.2", "4.1.3",
                                "4.2", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6",
                                "4.3", "4.3.1", "4.3.2", "4.3.3", "4.3.4", "4.3.5", "4.3.6",
                                "4.4", "4.4.1", "4.5", "4.5.1", "4.5.2", "4.5.3", "4.5.4", "4.5.5",
                                "4.5.6", "4.5.7", "4.5.8", "4.5.9", "4.5.10", "4.5.11", "4.5.12"
                        ))
                        .description("Apache HttpClient versions prior to version 4.5.13 and 5.0.3 can misinterpret malformed authority component in request URIs passed to the library as java.net.URI object and pick the wrong target host for request execution.")
                        .severity("MEDIUM")
                        .build(),

                // CVE-2020-8840 - FasterXML jackson-databind - Polymorphic Typing
                KnownCve.builder()
                        .cveId("CVE-2020-8840")
                        .groupId("com.fasterxml.jackson.core")
                        .artifactId("jackson-databind")
                        .vulnerableVersions(Arrays.asList(
                                "2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0", "2.7.0",
                                "2.8.0", "2.8.1", "2.8.2", "2.8.3", "2.8.4", "2.8.5", "2.8.6", "2.8.7", "2.8.8", "2.8.9",
                                "2.9.0", "2.9.1", "2.9.2", "2.9.3", "2.9.4", "2.9.5", "2.9.6", "2.9.7", "2.9.8", "2.9.9", "2.9.10"
                        ))
                        .description("FasterXML jackson-databind 2.0.0 through 2.9.10 mishandles the interaction between serialization gadgets and typing, related to com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.")
                        .severity("HIGH")
                        .build()
        );
    }
}