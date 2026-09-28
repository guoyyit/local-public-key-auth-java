package com.github.guoyyit.localpublickeyauthjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.function.Function;

/**
 * File-backed, single-lock transactional store.
 *
 * <p>All access is serialized by the store monitor, which makes every
 * read-modify-write sequence atomic (including monotonic counter updates).
 * Every successful mutation is durably persisted before returning: the new
 * state is written to a temporary file and atomically renamed over the store
 * file, so a crash can never leave a half-written JSON document.
 */
@Component
public class JsonFileStore {

    private static final Logger log = LoggerFactory.getLogger(JsonFileStore.class);

    private final AuthProperties properties;
    private final ObjectMapper mapper;
    private final Path file;

    private StoreData data;

    public JsonFileStore(AuthProperties properties) {
        this.properties = properties;
        this.mapper = new ObjectMapper();
        this.file = Path.of(properties.getStoreFile());
    }

    @PostConstruct
    synchronized void load() {
        if (Files.exists(file)) {
            try {
                this.data = mapper.readValue(file.toFile(), StoreData.class);
                log.info("Loaded auth store from {} ({} credentials, {} registrations, {} assertions)",
                        file, data.getCredentials().size(), data.getRegistrations().size(),
                        data.getAssertions().size());
            } catch (IOException e) {
                throw new IllegalStateException("failed to load auth store from " + file, e);
            }
        } else {
            this.data = new StoreData();
            log.info("No existing auth store at {}, starting empty", file);
        }
    }

    /**
     * Read state under the store lock. The action must not mutate the data.
     */
    public synchronized <T> T read(Function<StoreData, T> action) {
        return action.apply(data);
    }

    /**
     * Mutate state atomically. Persistence happens after the action returns;
     * if it throws, nothing is persisted and the exception propagates.
     */
    public synchronized <T> T mutate(Function<StoreData, T> action) {
        T result = action.apply(data);
        persist();
        return result;
    }

    /**
     * Force a durable write of the current state.
     */
    public synchronized void flush() {
        persist();
    }

    /**
     * Discard all data and persist the empty state. Primarily intended for
     * integration tests that need an isolated store.
     */
    public synchronized void reset() {
        this.data = new StoreData();
        persist();
    }

    private void persist() {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp." + Thread.currentThread().getId());

            byte[] json = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(data);
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(java.nio.ByteBuffer.wrap(json));
                channel.force(true);
            }
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("failed to persist auth store to " + file, e);
        }
    }
}
