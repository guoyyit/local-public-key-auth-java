package com.github.guoyyit.localpublickeyauthjava.web;

import com.github.guoyyit.localpublickeyauthjava.service.AuthService;
import com.github.guoyyit.localpublickeyauthjava.web.dto.CredentialView;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginAssertionRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginAssertionResponse;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginStartRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginStartResponse;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationCompleteRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationCompleteResponse;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationStartRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationStartResponse;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register/start")
    public RegistrationStartResponse registerStart(@RequestBody RegistrationStartRequest request) {
        return authService.startRegistration(request);
    }

    @PostMapping("/register/complete")
    public RegistrationCompleteResponse registerComplete(@RequestBody RegistrationCompleteRequest request) {
        return authService.completeRegistration(request);
    }

    @PostMapping("/login/start")
    public LoginStartResponse loginStart(@RequestBody LoginStartRequest request) {
        return authService.startLogin(request);
    }

    @PostMapping("/login/assert")
    public LoginAssertionResponse loginAssert(@RequestBody LoginAssertionRequest request) {
        return authService.verifyAssertion(request);
    }

    @GetMapping("/users/{userId}/credentials")
    public List<CredentialView> listCredentials(@PathVariable String userId) {
        return authService.listCredentials(userId);
    }

    @DeleteMapping("/users/{userId}/credentials/{credentialId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void disableCredential(@PathVariable String userId, @PathVariable String credentialId) {
        authService.disableCredential(userId, credentialId);
    }
}
