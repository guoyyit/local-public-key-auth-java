package com.github.guoyyit.localpublickeyauthjava.tests.support;

import com.github.guoyyit.localpublickeyauthjava.service.TimeProvider;

/**
 * Controllable clock for expiry-related tests.
 */
public class MutableTimeProvider extends TimeProvider {

    private volatile long current = System.currentTimeMillis();

    public void set(long millis) {
        this.current = millis;
    }

    public void advance(long millis) {
        this.current += millis;
    }

    @Override
    public long nowMillis() {
        return current;
    }
}
