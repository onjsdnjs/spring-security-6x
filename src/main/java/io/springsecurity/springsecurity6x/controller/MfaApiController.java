package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa")
public class MfaApiController {

    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter; // 응답 생성용
    private final MfaPolicyProvider mfaPolicyProvider; // 정책 검증용
    private final ApplicationContext applicationContext; // RP ID 등 설정값 접근용

    // EmailOneTimeTokenService는 OTT 코드 재발송 시에만 필요. 생성자 주입 (nullable 가능)
    @Nullable
    private final EmailOneTimeTokenService emailOttService;

    // Passkey Assertion Options 생성을 위해 실제로는 Spring Security WebAuthn 컴포넌트 주입 필요
    // 예: private final RelyingPartyRegistrationRepository relyingPartyRepository;
    // 예: private final OptionsChallengeGenerator assertionOptionsChallengeGenerator;
    // 예: private final WebAuthnCredentialRecordStore credentialStore;


    // 사용자가 MFA 인증 수단을 선택했을 때 호출되는 API
    @PostMapping("/select-factor")
    public ResponseEntity<?> handleFactorSelection(@RequestBody SelectFactorRequestDto selectRequest,
                                                   @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                                   HttpServletRequest request) {
        Assert.notNull(selectRequest, "SelectFactorRequestDto cannot be null.");
        Assert.hasText(selectRequest.factorType(), "factorType in SelectFactorRequestDto cannot be empty.");
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API Call: /api/mfa/select-factor. Selected Factor: {}, MFA Session ID: {}",
                selectRequest.factorType(), mfaSessionIdHeader);

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다."));
        }

        // 요청 사용자 이름과 컨텍스트 사용자 이름 일치 여부 확인 (선택적이지만 보안 강화)
        if (selectRequest.username() != null && !Objects.equals(factorContext.getUsername(), selectRequest.username())) {
            log.warn("MFA factor selection by user '{}' for MFA session of user '{}' (ID: {}). Forbidden.",
                    selectRequest.username(), factorContext.getUsername(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        // 현재 상태가 Factor 선택을 기다리는 상태인지 확인
        if (factorContext.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("MFA factor selection attempt in invalid state: {}. Session ID: {}", factorContext.getCurrentState(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(createErrorResponse("INVALID_MFA_STATE_FOR_SELECTION", "잘못된 MFA 진행 상태입니다."));
        }

        AuthType selectedFactor;
        try {
            selectedFactor = AuthType.valueOf(selectRequest.factorType().toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factorType received in select-factor request: {}. Session ID: {}", selectRequest.factorType(), mfaSessionIdHeader, e);
            return ResponseEntity.badRequest().body(createErrorResponse("INVALID_FACTOR_TYPE", "유효하지 않은 인증 수단입니다: " + selectRequest.factorType()));
        }

        // 선택한 Factor가 사용 가능한지 정책 제공자를 통해 확인
        if (!mfaPolicyProvider.isFactorAvailableForUser(factorContext.getUsername(), selectedFactor, factorContext)) {
            log.warn("User '{}' (session {}) selected factor {} which is not available/registered as per policy.",
                    factorContext.getUsername(), mfaSessionIdHeader, selectedFactor);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("UNAVAILABLE_FACTOR", "선택한 인증 수단(" + selectedFactor + ")은 현재 사용할 수 없습니다."));
        }

        factorContext.setCurrentProcessingFactor(selectedFactor);
        factorContext.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION); // 다음 상태: 이 Factor의 챌린지 UI 로드/초기화 대기
        contextPersistence.saveContext(factorContext, request);

        String nextUiPageUrl = request.getContextPath() + "/mfa/challenge/" + selectedFactor.name().toLowerCase();
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "FACTOR_SELECTED_PROCEED_TO_CHALLENGE");
        responseBody.put("message", selectedFactor.name() + " 인증을 시작합니다. 해당 페이지로 이동합니다.");
        responseBody.put("nextStepUrl", nextUiPageUrl);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());

        log.info("Factor {} selected for MFA session {}. Client will be guided to {}.", selectedFactor, mfaSessionIdHeader, nextUiPageUrl);
        return ResponseEntity.ok(responseBody);
    }

    // OTT 코드 재발송 요청 API
    @PostMapping("/request-ott-code")
    public ResponseEntity<?> requestMfaOttCode(@RequestBody OttCodeRequestDto ottRequestDto, // username은 FactorContext에서 가져오므로 DTO 불필요 가능
                                               @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                               HttpServletRequest request) {
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API Call: /api/mfa/request-ott-code. MFA Session ID: {}", mfaSessionIdHeader);

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다."));
        }

        // ottRequestDto.username()과 factorContext.getUsername() 일치 여부 확인 (선택적)
        if (ottRequestDto != null && ottRequestDto.username() != null && !Objects.equals(factorContext.getUsername(), ottRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        // 현재 처리 중인 Factor가 OTT이고, 상태가 챌린지 제시 상태인지 확인
        if (factorContext.getCurrentProcessingFactor() != AuthType.OTT ||
                factorContext.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            log.warn("OTT code resend requested in invalid state ({}) or for non-OTT factor ({}). Session ID: {}",
                    factorContext.getCurrentState(), factorContext.getCurrentProcessingFactor(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("INVALID_STATE_FOR_OTT_RESEND", "잘못된 상태에서 OTT 코드 재전송을 요청했습니다."));
        }

        if (emailOttService == null) {
            log.error("EmailOneTimeTokenService is not configured. Cannot resend OTT code. Session ID: {}", mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("OTT_SERVICE_UNCONFIGURED", "OTT 서비스가 설정되지 않았습니다."));
        }

        try {
            // 스프링 시큐리티의 OneTimeTokenService.generate()를 호출하여 코드 생성 및 발송 "요청"
            emailOttService.generate(new GenerateOneTimeTokenRequest(factorContext.getUsername()));
            log.info("MFA OTT code resend requested and sent to {} for session {}", factorContext.getUsername(), mfaSessionIdHeader);
            return ResponseEntity.ok(Map.of("message", "새로운 인증 코드가 " + factorContext.getUsername() + "(으)로 발송되었습니다."));
        } catch (Exception e) {
            log.error("Error requesting/sending MFA OTT code for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(createErrorResponse("OTT_RESEND_FAILED", "인증 코드 재전송에 실패했습니다: " + e.getMessage()));
        }
    }

    // MFA Passkey Assertion Options 요청 API
    @PostMapping("/assertion/options")
    public ResponseEntity<?> getMfaPasskeyAssertionOptions(@RequestBody(required = false) PasskeyOptionsRequestDto optionsRequestDto, // username은 컨텍스트에서 가져오므로 DTO 불필요 가능
                                                           @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                                           HttpServletRequest httpServletRequest) {
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API Call: /api/mfa/assertion/options. MFA Session ID: {}", mfaSessionIdHeader);

        FactorContext factorContext = contextPersistence.contextLoad(httpServletRequest);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다."));
        }

        if (optionsRequestDto != null && optionsRequestDto.username() != null && !Objects.equals(factorContext.getUsername(), optionsRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        if (factorContext.getCurrentProcessingFactor() != AuthType.PASSKEY ||
                !(factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                        factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) {
            log.warn("Passkey assertion options requested in invalid state ({}) or for non-Passkey factor ({}). Session ID: {}",
                    factorContext.getCurrentState(), factorContext.getCurrentProcessingFactor(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("INVALID_STATE_FOR_PASSKEY_OPTIONS", "잘못된 상태에서 Passkey 옵션 요청."));
        }

        // 실제 구현: Spring Security WebAuthn 컴포넌트 (RelyingPartyRegistrationRepository, OptionsChallengeGenerator 등)를 사용하여
        // Assertion Options를 생성하고 반환해야 합니다.
        // 이 예제에서는 임시로 간단한 챌린지만 생성합니다.
        try {
            // String rpId = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");
            // RelyingPartyRegistration relyingParty = relyingPartyRepository.findByRpId(rpId);
            // if (relyingParty == null) throw new IllegalStateException("RP not found for " + rpId);
            // AssertionOptions assertionOptions = assertionOptionsChallengeGenerator.generate(relyingParty, factorContext.getUsername());
            // return ResponseEntity.ok(assertionOptions.toMap()); // 또는 PublicKeyCredentialRequestOptions 객체 직접 반환

            // 임시 로직 (실제로는 스프링 시큐리티 WebAuthn 엔진 사용)
            String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(new SecureRandom().generateSeed(32));
            Map<String, Object> assertionOptionsMap = new HashMap<>();
            assertionOptionsMap.put("challenge", challenge);
            assertionOptionsMap.put("rpId", applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost"));
            // assertionOptionsMap.put("allowCredentials", ...); // 사용자의 등록된 credential 목록 (WebAuthnCredentialRecordStore 사용)
            assertionOptionsMap.put("userVerification", "preferred");
            assertionOptionsMap.put("timeout", 60000L);

            log.info("MFA Passkey assertion options (temporary) generated for user {} (session {})", factorContext.getUsername(), mfaSessionIdHeader);
            return ResponseEntity.ok(assertionOptionsMap);

        } catch (Exception e) {
            log.error("Error generating MFA Passkey assertion options for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(createErrorResponse("PASSKEY_OPTIONS_ERROR", "Passkey 옵션 생성에 실패했습니다: " + e.getMessage()));
        }
    }

    private Map<String, String> createErrorResponse(String errorCode, String message) {
        return Map.of("error", errorCode, "message", message);
    }

    // 요청 DTO 클래스들
    private record SelectFactorRequestDto(String factorType, @Nullable String username) {}
    private record OttCodeRequestDto(@Nullable String username) {} // username은 FactorContext에서 가져오므로 선택적
    private record PasskeyOptionsRequestDto(@Nullable String username) {} // username은 FactorContext에서 가져오므로 선택적
}