package com.github.guoyyit.localpublickeyauthjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private long registrationTtlSeconds = 300;
    private long assertionTtlSeconds = 120;
    private String expectedOrigin = "http://localhost:8080";
    private String storeFile = "./data/auth-store.json";
    private int recentCountersWindow = 128;

    public long getRegistrationTtlSeconds() { return registrationTtlSeconds; }
    public void setRegistrationTtlSeconds(long v) { this.registrationTtlSeconds = v; }

    public long getAssertionTtlSeconds() { return assertionTtlSeconds; }
    public void setAssertionTtlSeconds(long v) { this.assertionTtlSeconds = v; }

    public String getExpectedOrigin() { return expectedOrigin; }
    public void setExpectedOrigin(String v) { this.expectedOrigin = v; }

    public String getStoreFile() { return storeFile; }
    public void setStoreFile(String v) { this.storeFile = v; }

    public int getRecentCountersWindow() { return recentCountersWindow; }
    public void setRecentCountersWindow(int v) { this.recentCountersWindow = v; }
}
