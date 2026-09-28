package com.github.guoyyit.localpublickeyauthjava.domain;

import java.util.ArrayList;
import java.util.List;

/**
 * Root object persisted atomically to disk.
 */
public record StoreData(
        List<Credential> credentials,
        List<RegistrationSession> sessions,
        List<AuthChallenge> challenges) {

    public static StoreData empty() {
        return new StoreData(new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
    }
}
