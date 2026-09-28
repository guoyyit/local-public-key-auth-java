package com.github.guoyyit.localpublickeyauthjava.schedule;

import com.github.guoyyit.localpublickeyauthjava.service.AuthService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Periodically reclaims expired registration sessions and login challenges.
 */
@Component
public class ExpiredSessionCleaner {

    private final AuthService authService;

    public ExpiredSessionCleaner(AuthService authService) {
        this.authService = authService;
    }

    @Scheduled(fixedDelayString = "${auth.cleanup.fixed-delay-ms:60000}")
    public void cleanup() {
        authService.purgeExpired();
    }
}
