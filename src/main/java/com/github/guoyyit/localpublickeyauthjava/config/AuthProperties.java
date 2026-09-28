package com.github.guoyyit.localpublickeyauthjava.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties under the {@code auth.*} prefix.
 */
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    /** Time-to-live of registration sessions in seconds. */
    private long registrationTtlSeconds = 300;

    /** Time-to-live of login challenges in seconds. */
    private long challengeTtlSeconds = 300;

    /** Directory where the persistent JSON state file is stored. */
    private String dataDir = "data";

    /** Origins allowed to drive registration / assertion requests. */
    private List<String> allowedOrigins = new ArrayList<>(List.of("http://localhost:8080"));

    /** Max time (ms) an out-of-order concurrent assertion waits for earlier counters. */
    private long counterGapTimeoutMs = 2000;

    public long getRegistrationTtlSeconds() {
        return registrationTtlSeconds;
    }

    public void setRegistrationTtlSeconds(long registrationTtlSeconds) {
        this.registrationTtlSeconds = registrationTtlSeconds;
    }

    public long getChallengeTtlSeconds() {
        return challengeTtlSeconds;
    }

    public void setChallengeTtlSeconds(long challengeTtlSeconds) {
        this.challengeTtlSeconds = challengeTtlSeconds;
    }

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public List<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public long getCounterGapTimeoutMs() {
        return counterGapTimeoutMs;
    }

    public void setCounterGapTimeoutMs(long counterGapTimeoutMs) {
        this.counterGapTimeoutMs = counterGapTimeoutMs;
    }
}
