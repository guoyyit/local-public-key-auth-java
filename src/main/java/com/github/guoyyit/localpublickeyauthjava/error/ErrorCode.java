package com.github.guoyyit.localpublickeyauthjava.error;

import org.springframework.http.HttpStatus;

/**
 * Canonical error codes returned by the local public key authentication service.
 */
public enum ErrorCode {

    INVALID_REQUEST(HttpStatus.BAD_REQUEST),
    INVALID_ORIGIN(HttpStatus.BAD_REQUEST),
    MALFORMED_CREDENTIAL(HttpStatus.BAD_REQUEST),
    UNSUPPORTED_ALGORITHM(HttpStatus.BAD_REQUEST),
    CREDENTIAL_EXISTS(HttpStatus.CONFLICT),
    SESSION_NOT_FOUND(HttpStatus.GONE),
    SESSION_EXPIRED(HttpStatus.GONE),
    SESSION_ALREADY_USED(HttpStatus.CONFLICT),
    CHALLENGE_NOT_FOUND(HttpStatus.GONE),
    CHALLENGE_EXPIRED(HttpStatus.GONE),
    CHALLENGE_REPLAY(HttpStatus.CONFLICT),
    USER_MISMATCH(HttpStatus.FORBIDDEN),
    UNKNOWN_CREDENTIAL(HttpStatus.NOT_FOUND),
    CREDENTIAL_DISABLED(HttpStatus.FORBIDDEN),
    SIGNATURE_INVALID(HttpStatus.UNAUTHORIZED),
    CLONE_DETECTED(HttpStatus.CONFLICT),
    CONCURRENCY_CONFLICT(HttpStatus.CONFLICT),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR);

    private final HttpStatus httpStatus;

    ErrorCode(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }
}
