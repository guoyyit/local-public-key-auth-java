package com.github.guoyyit.localpublickeyauthjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import com.github.guoyyit.localpublickeyauthjava.domain.AuthChallenge;
import com.github.guoyyit.localpublickeyauthjava.domain.Credential;
import com.github.guoyyit.localpublickeyauthjava.domain.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.domain.StoreData;
import com.github.guoyyit.localpublickeyauthjava.error.AuthException;
import com.github.guoyyit.localpublickeyauthjava.error.ErrorCode;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * In-memory authentication state with crash-safe file persistence.
 *
 * <p>Every read or mutation runs while holding a single monitor lock, giving the service a
 * simple serializable transaction boundary. A mutation is persisted before the lock is
 * released, so an accepted change can never be lost and an incomplete registration can never
 * leave a half-written record behind: the whole {@link StoreData} document is written to a
 * temporary file and then swapped in with an atomic rename.
 */
@Component
public class AuthStore {

    private static final Logger log = LoggerFactory.getLogger(AuthStore.class);
    private static final String STATE_FILE = "auth-state.json";

    private final AuthProperties properties;
    private final ObjectMapper objectMapper;

    private final Object lock = new Object();
    private StoreData data;
    private Path stateFile;

    public AuthStore(AuthProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    void initialize() {
        try {
            Path dir = Path.of(properties.getDataDir());
            Files.createDirectories(dir);
            this.stateFile = dir.resolve(STATE_FILE);
            if (Files.exists(stateFile)) {
                this.data = load(stateFile);
                log.info("Restored authentication state from {} ({} credentials, {} sessions, {} challenges)",
                        stateFile.toAbsolutePath(),
                        data.credentials().size(),
                        data.sessions().size(),
                        data.challenges().size());
            } else {
                this.data = StoreData.empty();
                persistLocked();
                log.info("Initialized fresh authentication state at {}", stateFile.toAbsolutePath());
            }
        } catch (IOException ex) {
            throw new UncheckedIOException("failed to initialize authentication state", ex);
        }
    }

    private StoreData load(Path file) throws IOException {
        StoreData loaded = objectMapper.readValue(file.toFile(), StoreData.class);
        return new StoreData(
                loaded.credentials() == null ? new ArrayList<>() : new ArrayList<>(loaded.credentials()),
                loaded.sessions() == null ? new ArrayList<>() : new ArrayList<>(loaded.sessions()),
                loaded.challenges() == null ? new ArrayList<>() : new ArrayList<>(loaded.challenges()));
    }

    /** Executes a read-only function against a consistent snapshot. */
    public <T> T read(Function<StoreView, T> fn) {
        synchronized (lock) {
            return fn.apply(viewOf(data));
        }
    }

    /**
     * Executes a mutating function and atomically persists the resulting state before returning.
     *
     * <p>The callback runs against a working copy. If it throws (business validation failure),
     * the committed in-memory state is untouched and nothing is persisted: a transaction is
     * all-or-nothing. If the callback succeeds but persistence fails, state is reloaded from
     * the last good file so memory and disk never diverge.
     */
    public void mutate(Consumer<StoreView> fn) {
        synchronized (lock) {
            StoreData working = copyOf(data);
            try {
                fn.accept(viewOf(working));
            } catch (RuntimeException business) {
                // Discard the working copy entirely; committed state is unchanged.
                throw business;
            }
            try {
                this.data = working;
                persistLocked();
            } catch (RuntimeException persistence) {
                try {
                    this.data = Files.exists(stateFile) ? load(stateFile) : StoreData.empty();
                } catch (IOException loadEx) {
                    log.error("failed to reload state after persistence failure", loadEx);
                }
                throw persistence;
            }
        }
    }

    private static StoreData copyOf(StoreData source) {
        return new StoreData(
                new ArrayList<>(source.credentials()),
                new ArrayList<>(source.sessions()),
                new ArrayList<>(source.challenges()));
    }

    private void persistLocked() {
        try {
            Path temp = stateFile.resolveSibling(
                    STATE_FILE + ".tmp." + java.util.UUID.randomUUID());
            // A fresh writer per call avoids any shared-buffer reuse under concurrent callers.
            String json = objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(data);
            Files.writeString(temp, json, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(temp, stateFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temp, stateFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, "failed to persist authentication state", ex);
        }
    }

    private static StoreView viewOf(StoreData data) {
        return new StoreView() {
            @Override
            public List<Credential> credentials() {
                return data.credentials();
            }

            @Override
            public List<RegistrationSession> sessions() {
                return data.sessions();
            }

            @Override
            public List<AuthChallenge> challenges() {
                return data.challenges();
            }
        };
    }

    /**
     * Mutating accessor for the three state collections. Only valid inside a store callback.
     */
    public interface StoreView {
        List<Credential> credentials();
        List<RegistrationSession> sessions();
        List<AuthChallenge> challenges();
    }
}
