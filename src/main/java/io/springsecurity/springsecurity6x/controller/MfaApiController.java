package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa")
public class MfaApiController {

    private final ContextPersistence contextPersistence;
    private final EmailOneTimeTokenService emailOttService;
    private final AuthContextProperties authContextProperties;
    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    // WebAuthnCredentialRecordStore는 사용자의 등록된 Passkey ID 목록(allowCredentials)을 가져올 때 필요. 자동 설정 또는 명시적 Bean 주입.
    private final WebAuthnCredentialRecordStore webAuthnCredentialRecordStore;
    private final ApplicationContext applicationContext; // RP ID 기본값 조회용

    @PostMapping("/select-factor")
    public ResponseEntity<?> handleFactorSelection(@RequestBody SelectFactorRequestDto selectRequest,
                                                   @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                                   HttpServletRequest request) {
        Assert.notNull(selectRequest, "SelectFactorRequestDto cannot be null.");
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API: /api/mfa/select-factor received for factor: {} for session: {}", selectRequest.factorType(), mfaSessionIdHeader);

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "MFA_SESSION_INVALID", "message", "MFA 세션이 유효하지 않습니다."));
        }
        String usernameFromContext = factorContext.getUsername();
        if (selectRequest.username() != null && !Objects.equals(usernameFromContext, selectRequest.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "USER_MISMATCH", "message", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        try {
            AuthType selectedFactor = AuthType.valueOf(selectRequest.factorType().toUpperCase());
            factorContext.setCurrentProcessingFactor(selectedFactor);
            contextPersistence.saveContext(factorContext, request);

            String nextUiPageUrl;
            String message = selectedFactor.name() + " 인증을 준비합니다. 해당 페이지로 이동합니다.";

            if (selectedFactor == AuthType.OTT) {
                nextUiPageUrl = "/mfa/verify/ott";
            } else if (selectedFactor == AuthType.PASSKEY) {
                nextUiPageUrl = "/mfa/verify/passkey";
            } else {
                log.warn("Unsupported factor type selected: {} for session {}", selectedFactor, mfaSessionIdHeader);
                return ResponseEntity.badRequest().body(Map.of("error", "UNSUPPORTED_FACTOR", "message", "지원하지 않는 2차 인증 수단입니다."));
            }
            log.info("Factor {} selected for MFA session {}. Client will be guided to {}.", selectedFactor, mfaSessionIdHeader, nextUiPageUrl);
            return ResponseEntity.ok(Map.of(
                    "nextStepUrl", nextUiPageUrl,
                    "message", message,
                    "mfaSessionId", factorContext.getMfaSessionId()
            ));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factorType received in select-factor request: {}", selectRequest.factorType(), e);
            return ResponseEntity.badRequest().body(Map.of("error", "INVALID_FACTOR_TYPE", "message", "유효하지 않은 인증 수단입니다."));
        }
    }

    @PostMapping("/request-ott-code")
    public ResponseEntity<?> requestMfaOttCode(@RequestBody OttCodeRequestDto ottRequestDto,
                                               @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                               HttpServletRequest request) {
        Assert.notNull(ottRequestDto, "OttCodeRequestDto cannot be null.");
        Assert.hasText(ottRequestDto.username(), "Username in OttCodeRequestDto cannot be empty.");
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API: /api/mfa/request-ott-code received for user: {} for session: {}", ottRequestDto.username(), mfaSessionIdHeader);
        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "MFA_SESSION_INVALID", "message", "MFA 세션이 유효하지 않습니다."));
        }
        if (!Objects.equals(factorContext.getUsername(), ottRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "USER_MISMATCH", "message", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        try {
            GenerateOneTimeTokenRequest tokenRequest = new GenerateOneTimeTokenRequest(ottRequestDto.username()
            );
            emailOttService.generate(tokenRequest);
            log.info("MFA OTT code requested and sent to {} for session {}", ottRequestDto.username(), mfaSessionIdHeader);
            return ResponseEntity.ok(Map.of("message", "새로운 인증 코드가 " + ottRequestDto.username() + "(으)로 발송되었습니다."));
        } catch (Exception e) {
            log.error("Error requesting/sending MFA OTT code for user {}: {}", ottRequestDto.username(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("error", "OTT_REQUEST_FAILED", "message", "인증 코드 요청에 실패했습니다: " + e.getMessage()));
        }
    }

    @PostMapping("/assertion/options") // MFA Passkey 용
    public ResponseEntity<?> getMfaPasskeyAssertionOptions(@RequestBody PasskeyOptionsRequestDto optionsRequestDto,
                                                           @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                                           HttpServletRequest httpServletRequest) {
        Assert.notNull(optionsRequestDto, "PasskeyOptionsRequestDto cannot be null.");
        Assert.hasText(optionsRequestDto.username(), "Username in PasskeyOptionsRequestDto cannot be empty.");
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API: /api/mfa/assertion/options received for user: {} for session: {}", optionsRequestDto.username(), mfaSessionIdHeader);
        FactorContext factorContext = contextPersistence.contextLoad(httpServletRequest);

        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "MFA_SESSION_INVALID", "message", "MFA 세션이 유효하지 않습니다."));
        }
        if (!Objects.equals(factorContext.getUsername(), optionsRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "USER_MISMATCH", "message", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        try {
            String rpIdFromServer = httpServletRequest.getServerName(); // 현재 요청 호스트 사용
            RelyingPartyRegistration relyingParty = relyingPartyRegistrationRepository.findByRpId(rpIdFromServer);
            if (relyingParty == null) {
                rpIdFromServer = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");
                relyingParty = relyingPartyRegistrationRepository.findByRpId(rpIdFromServer);
                if (relyingParty == null) {
                    log.error("RelyingPartyRegistration not found for RP ID: {}", rpIdFromServer);
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "RP_NOT_FOUND", "message", "Passkey 신뢰 당사자(RP) 설정을 찾을 수 없습니다."));
                }
            }

            // 사용자의 등록된 credential ID 목록 조회
            List<WebAuthnCredentialRecord> credentialRecords = webAuthnCredentialRecordStore.get(optionsRequestDto.username());
            List<PublicKeyCredentialDescriptor> allowCredentials = credentialRecords.stream()
                    .map(record -> PublicKeyCredentialDescriptor.builder().id(record.getCredentialId()).build())
                    .collect(Collectors.toList());

            PublicKeyCredentialRequestOptions.Builder optionsBuilder = PublicKeyCredentialRequestOptions.builder()
                    .challenge(generateRandomChallenge()) // 랜덤 챌린지 (Base64URL 인코딩된 문자열)
                    .rpId(relyingParty.getId());

            if (!allowCredentials.isEmpty()) {
                optionsBuilder.allowCredentials(allowCredentials);
            }
            // RP에 설정된 UserVerificationRequirement 사용 (또는 기본값)
            optionsBuilder.userVerification(relyingParty.getAuthenticationUserVerification());
            // RP에 설정된 타임아웃 사용 (또는 기본값)
            if (relyingParty.getAuthenticationTimeout() != null) {
                optionsBuilder.timeout(relyingParty.getAuthenticationTimeout().toMillis());
            }

            PublicKeyCredentialRequestOptions assertionOptions = optionsBuilder.build();

            log.info("MFA Passkey assertion options generated for user {} (session {})", optionsRequestDto.username(), mfaSessionIdHeader);
            // 클라이언트에 전달하기 전에 challenge와 allowCredentials의 id를 Base64URL 문자열로 변환할 필요 없음
            // PublicKeyCredentialRequestOptions 객체 자체가 직렬화되어 전달됨 (내부적으로 Base64URL로 되어 있음)
            return ResponseEntity.ok(assertionOptions.toMap());
        } catch (Exception e) {
            log.error("Error generating MFA Passkey assertion options for user {}: {}", optionsRequestDto.username(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("error", "PASSKEY_OPTIONS_ERROR", "message", "Passkey 옵션 생성에 실패했습니다: " + e.getMessage()));
        }
    }

    private String generateRandomChallenge() {
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
    }

    private record SelectFactorRequestDto(String factorType, String username) {}
    private record OttCodeRequestDto(String username) {}
    private record PasskeyOptionsRequestDto(String username) {}
}