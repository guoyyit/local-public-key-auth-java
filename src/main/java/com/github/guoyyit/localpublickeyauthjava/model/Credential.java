package com.github.guoyyit.localpublickeyauthjava.model;

import java.util.LinkedHashSet;
import java.util.Set;

public class Credential {
    private String credentialId;
    private String userId;
    private String publicKey;
    private long counter;
    private CredentialStatus status;
    private Set<Long> recentCounters = new LinkedHashSet<>();
    private long createdAt;
    private long updatedAt;

    public Credential() {}

    public Credential(String credentialId, String userId, String publicKey, long counter,
                      CredentialStatus status, long createdAt, long updatedAt) {
        this.credentialId = credentialId;
        this.userId = userId;
        this.publicKey = publicKey;
        this.counter = counter;
        this.status = status;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String v) { this.credentialId = v; }
    public String getUserId() { return userId; }
    public void setUserId(String v) { this.userId = v; }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String v) { this.publicKey = v; }
    public long getCounter() { return counter; }
    public void setCounter(long v) { this.counter = v; }
    public CredentialStatus getStatus() { return status; }
    public void setStatus(CredentialStatus v) { this.status = v; }
    public Set<Long> getRecentCounters() { return recentCounters; }
    public void setRecentCounters(Set<Long> v) { this.recentCounters = v; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long v) { this.createdAt = v; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long v) { this.updatedAt = v; }
}
