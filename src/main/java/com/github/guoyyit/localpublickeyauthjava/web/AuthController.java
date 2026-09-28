package com.github.guoyyit.localpublickeyauthjava.web;

import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.AssertionChallenge;
import com.github.guoyyit.localpublickeyauthjava.model.Credential;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.model.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.service.AuthenticationService;
import com.github.guoyyit.localpublickeyauthjava.service.ChallengeService;
import com.github.guoyyit.localpublickeyauthjava.service.CredentialService;
import com.github.guoyyit.localpublickeyauthjava.web.dto.Dtos;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final ChallengeService challenges;
    private final CredentialService credentials;
    private final AuthenticationService authentication;

    public AuthController(ChallengeService challenges, CredentialService credentials,
                          AuthenticationService authentication) {
        this.challenges = challenges;
        this.credentials = credentials;
        this.authentication = authentication;
    }

    @PostMapping("/register/start")
    public Dtos.RegistrationStartResponse registerStart(@RequestBody Dtos.RegistrationStartRequest req) {
        requireNonNull(req);
        RegistrationSession session = challenges.createRegistration(req.userId(), req.origin());
        return new Dtos.RegistrationStartResponse(
                session.getSessionId(), session.getChallenge(), session.getExpiresAt());
    }

    @PostMapping("/register/complete")
    public Dtos.RegistrationCompleteResponse registerComplete(@RequestBody Dtos.RegistrationCompleteRequest req) {
        requireNonNull(req);
        Credential credential = credentials.register(req.userId(), req.sessionId(), req.origin(),
                req.credentialId(), req.publicKey(), req.signature());
        return new Dtos.RegistrationCompleteResponse(
                credential.getCredentialId(), credential.getUserId(), credential.getStatus().name());
    }

    @PostMapping("/assert/start")
    public Dtos.AssertionStartResponse assertStart(@RequestBody Dtos.AssertionStartRequest req) {
        requireNonNull(req);
        AssertionChallenge challenge = challenges.createAssertion(req.userId(), req.origin());
        return new Dtos.AssertionStartResponse(
                challenge.getChallengeId(), challenge.getChallenge(), challenge.getExpiresAt());
    }

    @PostMapping("/assert/verify")
    public Dtos.AssertionVerifyResponse assertVerify(@RequestBody Dtos.AssertionVerifyRequest req) {
        requireNonNull(req);
        boolean ok = authentication.authenticate(req.userId(), req.challengeId(), req.credentialId(),
                req.counter(), req.signature(), req.origin());
        return new Dtos.AssertionVerifyResponse(ok, req.credentialId(), req.counter());
    }

    @GetMapping("/credentials")
    public List<Dtos.CredentialView> list(@RequestParam String userId) {
        return credentials.list(userId).stream()
                .map(AuthController::toView)
                .toList();
    }

    @PostMapping("/credentials/{credentialId}/disable")
    public Dtos.MessageResponse disable(@RequestParam String userId,
                                        @PathVariable String credentialId) {
        credentials.disable(userId, credentialId);
        return new Dtos.MessageResponse("DISABLED");
    }

    @PostMapping("/credentials/{credentialId}/revoke")
    public Dtos.MessageResponse revoke(@RequestParam String userId,
                                       @PathVariable String credentialId) {
        credentials.revoke(userId, credentialId);
        return new Dtos.MessageResponse("REVOKED");
    }

    private static Dtos.CredentialView toView(Credential c) {
        return new Dtos.CredentialView(c.getCredentialId(), c.getUserId(), c.getStatus().name(),
                c.getCounter(), c.getCreatedAt(), c.getUpdatedAt());
    }

    private static void requireNonNull(Object req) {
        if (req == null) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "request body is required");
        }
    }
}
