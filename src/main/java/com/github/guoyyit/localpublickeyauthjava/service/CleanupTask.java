package com.github.guoyyit.localpublickeyauthjava.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Periodically reclaims expired registration sessions and assertion challenges.
 */
@Component
public class CleanupTask {

    private static final Logger log = LoggerFactory.getLogger(CleanupTask.class);

    private final ChallengeService challenges;

    public CleanupTask(ChallengeService challenges) {
        this.challenges = challenges;
    }

    @Scheduled(fixedDelayString = "${auth.cleanup-interval-ms:60000}")
    public void purge() {
        int removed = challenges.purgeExpired();
        if (removed > 0) {
            log.debug("Purged {} expired auth sessions/challenges", removed);
        }
    }
}
