package com.github.guoyyit.localpublickeyauthjava.web;

import com.github.guoyyit.localpublickeyauthjava.error.AuthException;
import com.github.guoyyit.localpublickeyauthjava.error.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.web.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.ResponseEntity;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuth(AuthException ex) {
        return build(ex.errorCode(), ex.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return build(ErrorCode.INVALID_REQUEST, "malformed or missing JSON request body");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex) {
        return build(ErrorCode.INTERNAL_ERROR, "internal server error");
    }

    private ResponseEntity<ErrorResponse> build(ErrorCode code, String message) {
        return ResponseEntity.status(code.httpStatus()).body(new ErrorResponse(code.name(), message));
    }
}
