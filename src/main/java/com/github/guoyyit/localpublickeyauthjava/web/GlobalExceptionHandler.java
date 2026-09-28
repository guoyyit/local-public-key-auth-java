package com.github.guoyyit.localpublickeyauthjava.web;

import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Map<ErrorCode, HttpStatus> STATUS = Map.ofEntries(
            Map.entry(ErrorCode.INVALID_REQUEST, HttpStatus.BAD_REQUEST),
            Map.entry(ErrorCode.INVALID_PUBLIC_KEY, HttpStatus.BAD_REQUEST),
            Map.entry(ErrorCode.UNKNOWN_USER, HttpStatus.NOT_FOUND),
            Map.entry(ErrorCode.CREDENTIAL_NOT_FOUND, HttpStatus.NOT_FOUND),
            Map.entry(ErrorCode.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND),
            Map.entry(ErrorCode.CHALLENGE_EXPIRED, HttpStatus.GONE),
            Map.entry(ErrorCode.CHALLENGE_CONSUMED, HttpStatus.CONFLICT),
            Map.entry(ErrorCode.CHALLENGE_USER_MISMATCH, HttpStatus.FORBIDDEN),
            Map.entry(ErrorCode.ORIGIN_MISMATCH, HttpStatus.FORBIDDEN),
            Map.entry(ErrorCode.INVALID_SIGNATURE, HttpStatus.UNAUTHORIZED),
            Map.entry(ErrorCode.CREDENTIAL_REVOKED, HttpStatus.FORBIDDEN),
            Map.entry(ErrorCode.CREDENTIAL_ALREADY_EXISTS, HttpStatus.CONFLICT),
            Map.entry(ErrorCode.COUNTER_CLONE_DETECTED, HttpStatus.UNAUTHORIZED),
            Map.entry(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR)
    );

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handle(ApiException ex) {
        HttpStatus status = STATUS.getOrDefault(ex.getCode(), HttpStatus.INTERNAL_SERVER_ERROR);
        return ResponseEntity.status(status)
                .body(new ErrorResponse(ex.getCode().name(), ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest()
                .body(new ErrorResponse(ErrorCode.INVALID_REQUEST.name(), "malformed JSON request"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse(ErrorCode.INTERNAL_ERROR.name(), "internal error"));
    }
}
