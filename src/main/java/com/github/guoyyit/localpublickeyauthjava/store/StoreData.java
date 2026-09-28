package com.github.guoyyit.localpublickeyauthjava.store;

import com.github.guoyyit.localpublickeyauthjava.model.AssertionChallenge;
import com.github.guoyyit.localpublickeyauthjava.model.Credential;
import com.github.guoyyit.localpublickeyauthjava.model.RegistrationSession;

import java.util.LinkedHashMap;
import java.util.Map;

public class StoreData {
    private Map<String, Credential> credentials = new LinkedHashMap<>();
    private Map<String, RegistrationSession> registrations = new LinkedHashMap<>();
    private Map<String, AssertionChallenge> assertions = new LinkedHashMap<>();

    public Map<String, Credential> getCredentials() { return credentials; }
    public void setCredentials(Map<String, Credential> v) { this.credentials = v; }
    public Map<String, RegistrationSession> getRegistrations() { return registrations; }
    public void setRegistrations(Map<String, RegistrationSession> v) { this.registrations = v; }
    public Map<String, AssertionChallenge> getAssertions() { return assertions; }
    public void setAssertions(Map<String, AssertionChallenge> v) { this.assertions = v; }
}
