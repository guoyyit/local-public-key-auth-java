package com.github.guoyyit.localpublickeyauthjava.model;

public class AssertionChallenge implements Expirable {
    private String challengeId;
    private String userId;
    private String challenge;
    private String origin;
    private long createdAt;
    private long expiresAt;
    private boolean consumed;

    public AssertionChallenge() {}

    public AssertionChallenge(String challengeId, String userId, String challenge, String origin,
                              long createdAt, long expiresAt) {
        this.challengeId = challengeId;
        this.userId = userId;
        this.challenge = challenge;
        this.origin = origin;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.consumed = false;
    }

    public String getChallengeId() { return challengeId; }
    public void setChallengeId(String v) { this.challengeId = v; }
    public String getUserId() { return userId; }
    public void setUserId(String v) { this.userId = v; }
    public String getChallenge() { return challenge; }
    public void setChallenge(String v) { this.challenge = v; }
    public String getOrigin() { return origin; }
    public void setOrigin(String v) { this.origin = v; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long v) { this.createdAt = v; }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long v) { this.expiresAt = v; }
    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean v) { this.consumed = v; }
}
