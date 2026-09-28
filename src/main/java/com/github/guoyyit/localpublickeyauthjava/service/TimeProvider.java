package com.github.guoyyit.localpublickeyauthjava.service;

import org.springframework.stereotype.Component;

@Component
public class TimeProvider {
    public long nowMillis() {
        return System.currentTimeMillis();
    }
}
