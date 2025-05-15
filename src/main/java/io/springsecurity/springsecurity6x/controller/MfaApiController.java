package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa")
public class MfaApiController {

    private final ContextPersistence contextPersistence;
    private final StateMachineManager stateMachineManager;
    private final EmailOneTimeTokenService emailOttService; // For requesting OTT code
    private final WebAuthnServer webAuthnServer; // For requesting Passkey options

    @PostMapping("/select-factor")
    public ResponseEntity<?> handleFactorSelection(@RequestBody SelectFactorRequestDto selectRequest,
                                                   @RequestHeader(name = "X-MFA-Session-Id", required = false) String mfaSessionIdHeader,
                                                   HttpServletRequest request) {
        log.info("API: /api/mfa/select-factor received for factor: {}", selectRequest.factorType());
        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "MFA_SESSION_INVALID", "message", "MFA 세션이 유효하지 않습니다."));
        }
        if (!factorContext.getUsername().equals(selectRequest.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "USER_MISMATCH", "message", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        try {
            AuthType selectedFactor = AuthType.valueOf(selectRequest.factorType().toUpperCase());
            factorContext.setCurrentProcessingFactor(selectedFactor);

            MfaState nextState = stateMachineManager.nextState(factorContext.getCurrentState(), MfaEvent.FACTOR_SELECTED);
            factorContext.changeState(nextState);
            contextPersistence.saveContext(factorContext, request);

            String nextHtmlPageUrl; // 클라이언트가 이동할 다음 UI 페이지
            if (selectedFactor == AuthType.OTT) {
                nextHtmlPageUrl = "/mfa/verify/ott";
            } else if (selectedFactor == AuthType.PASSKEY) {
                nextHtmlPageUrl = "/mfa/verify/passkey";
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "UNSUPPORTED_FACTOR", "message", "지원하지 않는 인증 수단입니다."));
            }
            log.info("Factor {} selected. Guiding client to {}. Session: {}", selectedFactor, nextHtmlPageUrl, factorContext.getMfaSessionId());
            return ResponseEntity.ok(Map.of("nextStepUrl", nextHtmlPageUrl, "mfaSessionId", factorContext.getMfaSessionId()));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "INVALID_FACTOR_TYPE", "message", "유효하지 않은 인증 수단입니다."));
        } catch (InvalidTransitionException e) {
            log.error("Invalid MFA state transition during factor selection: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "MFA_STATE_TRANSITION_ERROR", "message", "MFA 상태 전이 중 오류가 발생했습니다."));
        }
    }

    @PostMapping("/request-ott-code")
    public ResponseEntity<?> requestOttCode(@RequestBody OttCodeRequestDto ottRequestDto,
                                            @RequestHeader(name = "X-MFA-Session-Id", required = false) String mfaSessionIdHeader,
                                            HttpServletRequest request) {
        log.info("API: /api/mfa/request-ott-code received for user: {}", ottRequestDto.username());
        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "MFA_SESSION_INVALID", "message", "MFA 세션이 유효하지 않습니다."));
        }
        if (!factorContext.getUsername().equals(ottRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "USER_MISMATCH", "message", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }
        if (factorContext.getCurrentProcessingFactor() != AuthType.OTT) {
            return ResponseEntity.badRequest().body(Map.of("error", "INVALID_FACTOR_FOR_OTT", "message", "현재 OTT 인증 단계가 아닙니다."));
        }

        try {
            GenerateOneTimeTokenRequest tokenRequest = new GenerateOneTimeTokenRequest(ottRequestDto.username(), 300); // 5분 유효
            emailOttService.generate(tokenRequest); // 이메일 발송
            log.info("MFA OTT code requested and sent to {} for session {}", ottRequestDto.username(), factorContext.getMfaSessionId());

            // 상태 전이 (FACTOR_CHALLENGE_INITIATED 로 유지 또는 명시적 갱신)
            // MfaEvent.REQUEST_CHALLENGE 또는 CHALLENGE_DELIVERED 와 같은 이벤트로 상태 갱신 가능
            MfaState nextState = stateMachineManager.nextState(factorContext.getCurrentState(), MfaEvent.CHALLENGE_DELIVERED); // 예시 이벤트
            factorContext.changeState(nextState);
            contextPersistence.saveContext(factorContext, request);

            return ResponseEntity.ok(Map.of("message", "인증 코드가 이메일로 발송되었습니다."));
        } catch (Exception e) {
            log.error("Error requesting/sending OTT code for user {}: {}", ottRequestDto.username(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("error", "OTT_REQUEST_FAILED", "message", "인증 코드 요청에 실패했습니다."));
        }
    }

    @PostMapping("/assertion/options") // Passkey Assertion Options 요청 (MFA용)
    public ResponseEntity<?> getMfaPasskeyAssertionOptions(@RequestBody PasskeyOptionsRequestDto optionsRequestDto,
                                                           @RequestHeader(name = "X-MFA-Session-Id", required = false) String mfaSessionIdHeader,
                                                           HttpServletRequest request) {
        log.info("API: /api/mfa/assertion/options received for user: {}", optionsRequestDto.username());
        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "MFA_SESSION_INVALID", "message", "MFA 세션이 유효하지 않습니다."));
        }
        if (optionsRequestDto.username() != null && !factorContext.getUsername().equals(optionsRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "USER_MISMATCH", "message", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }
        if (factorContext.getCurrentProcessingFactor() != AuthType.PASSKEY) {
            return ResponseEntity.badRequest().body(Map.of("error", "INVALID_FACTOR_FOR_PASSKEY_OPTIONS", "message", "현재 Passkey 인증 단계가 아닙니다."));
        }

        try {
            String effectiveUsername = StringUtils.hasText(optionsRequestDto.username()) ? optionsRequestDto.username() : factorContext.getUsername();
            // WebAuthnServer를 사용하여 Assertion Options 생성
            PublicKeyCredentialRequestOptions assertionOptions = webAuthnServer.optionsRequest(
                    new ServerPublicKeyCredentialRequestOptionsResponse.Assertion(effectiveUsername)
            );
            log.info("MFA Passkey assertion options generated for user {} (session {})", effectiveUsername, factorContext.getMfaSessionId());

            // 상태 전이 (FACTOR_CHALLENGE_INITIATED 로 유지 또는 명시적 갱신)
            MfaState nextState = stateMachineManager.nextState(factorContext.getCurrentState(), MfaEvent.CHALLENGE_INITIATED); // 예시 이벤트
            factorContext.changeState(nextState);
            contextPersistence.saveContext(factorContext, request);

            return ResponseEntity.ok(assertionOptions.toMap()); // 클라이언트 JS가 사용할 수 있는 형태로 변환
        } catch (Exception e) {
            log.error("Error generating MFA Passkey assertion options for user {}: {}", optionsRequestDto.username(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("error", "PASSKEY_OPTIONS_ERROR", "message", "Passkey 옵션 생성에 실패했습니다."));
        }
    }


    // DTO 정의
    private record SelectFactorRequestDto(String factorType, String username) {}
    private record OttCodeRequestDto(String username) {}
    private record PasskeyOptionsRequestDto(String username) {} // username은 선택적일 수 있음
}
