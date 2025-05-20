package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
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
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa") // 기본 경로
public class MfaApiController {

    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties; // 추가

    @Nullable
    private final EmailOneTimeTokenService emailOttService; // MFA OTT 코드 생성/발송용

    // Passkey Assertion Options 생성은 Spring Security WebAuthn 컴포넌트 사용 권장
    // private final RelyingPartyRegistrationRepository relyingPartyRepository;
    // private final OptionsChallengeGenerator assertionOptionsChallengeGenerator;


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
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader) ||
                !StringUtils.hasText(factorContext.getFlowTypeName())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID", "MFA 세션이 유효하지 않거나 플로우 정보가 없습니다."));
        }
        // username 검증 (선택적이지만 권장)
        if (selectRequest.username() != null && !Objects.equals(factorContext.getUsername(), selectRequest.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }
        if (factorContext.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(createErrorResponse("INVALID_MFA_STATE_FOR_SELECTION", "잘못된 MFA 진행 상태입니다 (현재 상태: " + factorContext.getCurrentState() + ")."));
        }

        AuthType selectedFactorType;
        try {
            selectedFactorType = AuthType.valueOf(selectRequest.factorType().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(createErrorResponse("INVALID_FACTOR_TYPE", "유효하지 않은 인증 수단입니다: " + selectRequest.factorType()));
        }

        if (!mfaPolicyProvider.isFactorAvailableForUser(factorContext.getUsername(), selectedFactorType, factorContext)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("UNAVAILABLE_FACTOR", "선택한 인증 수단(" + selectedFactorType + ")은 현재 사용할 수 없습니다."));
        }

        AuthenticationFlowConfig currentFlowConfig = findFlowConfigByName(factorContext.getFlowTypeName());
        if (currentFlowConfig == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("MFA_FLOW_CONFIG_MISSING_SELECT", "MFA 플로우 설정을 찾을 수 없습니다."));
        }

        Optional<AuthenticationStepConfig> selectedStepOpt = findStepConfigByFactorTypeAndMinOrder(currentFlowConfig, selectedFactorType, 0); // MFA는 1차 인증(order 0) 이후

        if (selectedStepOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("MFA_STEP_CONFIG_MISSING", "선택한 인증 단계 설정을 찾을 수 없습니다."));
        }

        AuthenticationStepConfig selectedStep = selectedStepOpt.get();
        factorContext.setCurrentProcessingFactor(selectedFactorType);
        factorContext.setCurrentStepId(selectedStep.getStepId()); // <<-- currentStepId 설정
        if (currentFlowConfig.getRegisteredFactorOptions() != null) {
            factorContext.setCurrentFactorOptions(currentFlowConfig.getRegisteredFactorOptions().get(selectedFactorType));
        }
        factorContext.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        contextPersistence.saveContext(factorContext, request);

        // 클라이언트가 다음으로 이동할 UI 페이지 URL 결정
        String nextUiPageUrl;
        if (selectedFactorType == AuthType.OTT) {
            // OTT의 경우, 코드 생성 요청 UI로 먼저 안내
            nextUiPageUrl = request.getContextPath() + "/mfa/ott/request-code-ui";
        } else {
            // 다른 Factor는 해당 Factor의 챌린지 입력 UI로 바로 안내
            nextUiPageUrl = request.getContextPath() + "/mfa/challenge/" + selectedFactorType.name().toLowerCase();
        }

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "FACTOR_SELECTED_PROCEED_TO_CHALLENGE_UI");
        responseBody.put("message", selectedFactorType.name() + " 인증을 준비합니다. 해당 페이지로 이동합니다.");
        responseBody.put("nextStepUrl", nextUiPageUrl);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("nextFactorType", selectedFactorType.name().toUpperCase());
        responseBody.put("nextStepId", selectedStep.getStepId());

        log.info("Factor {} (stepId: {}) selected for MFA session {}. Client will be guided to {}.",
                selectedFactorType, selectedStep.getStepId(), mfaSessionIdHeader, nextUiPageUrl);
        return ResponseEntity.ok(responseBody);
    }

    // MFA 플로우 내 OTT 코드 "재전송" 또는 "최초 전송" 요청 API
    @PostMapping("/request-ott-code")
    public ResponseEntity<?> requestMfaOttCode(@RequestBody OttCodeRequestDto ottRequestDto,
                                               @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                               HttpServletRequest request) {
        Assert.hasText(mfaSessionIdHeader, "X-MFA-Session-Id header cannot be empty.");
        log.info("API Call: /api/mfa/request-ott-code. MFA Session ID: {}", mfaSessionIdHeader);

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다."));
        }
        // username 검증 (선택적)
        if (ottRequestDto != null && ottRequestDto.username() != null && !Objects.equals(factorContext.getUsername(), ottRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        // 이 API는 사용자가 OTT 코드 입력 UI에 있고, 코드를 받지 못했거나 재전송을 원할 때 호출됨.
        // 또는, /mfa/ott/request-code-ui 페이지에서 이메일 제출 후 호출되어 코드 발송을 트리거할 수도 있음.
        // 상태 검증: AWAITING_FACTOR_CHALLENGE_INITIATION (코드 요청 UI에서 최초 요청 시) 또는
        //           FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION (코드 입력 UI에서 재전송 요청 시)
        if (factorContext.getCurrentProcessingFactor() != AuthType.OTT ||
                !(factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                        factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) {
            log.warn("OTT code request in invalid state ({}) or for non-OTT factor ({}). Session ID: {}",
                    factorContext.getCurrentState(), factorContext.getCurrentProcessingFactor(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("INVALID_STATE_FOR_OTT_REQUEST", "잘못된 상태에서 OTT 코드 요청."));
        }

        if (emailOttService == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("OTT_SERVICE_UNCONFIGURED", "OTT 서비스가 설정되지 않았습니다."));
        }

        try {
            // Spring Security의 OneTimeTokenService.generate() 호출하여 코드 생성 및 발송
            // EmailOneTimeTokenService는 내부적으로 codeStore에 코드와 토큰을 저장하고 이메일 발송
            emailOttService.generate(new GenerateOneTimeTokenRequest(factorContext.getUsername()));

            // 코드 발송 성공 후, FactorContext 상태를 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION으로 변경 (UI는 이미 이 상태일 수 있음)
            // MfaContinuationFilter가 /mfa/challenge/ott (GET) 요청을 처리할 때 이 상태로 변경하므로, 여기서는 불필요할 수 있음.
            // 하지만 이 API가 코드 생성의 유일한 지점이라면, 여기서 상태 변경 필요.
            // --> MfaContinuationFilter가 UI 로드 시 상태를 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION으로 변경한다고 가정.

            log.info("MFA OTT code requested and sent to {} for session {}", factorContext.getUsername(), mfaSessionIdHeader);
            return ResponseEntity.ok(Map.of("status", "OTT_CODE_SENT", "message", "새로운 인증 코드가 " + factorContext.getUsername() + "(으)로 발송되었습니다."));
        } catch (Exception e) {
            log.error("Error requesting/sending MFA OTT code for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(createErrorResponse("OTT_REQUEST_FAILED", "인증 코드 요청/발송에 실패했습니다: " + e.getMessage()));
        }
    }

    // ... (getMfaPasskeyAssertionOptions, createErrorResponse, DTO 레코드들, findFlowConfigByName, findStepConfigByFactorTypeAndMinOrder는 이전 답변과 유사하게 유지) ...
    @PostMapping("/assertion/options")
    public ResponseEntity<?> getMfaPasskeyAssertionOptions(@RequestBody(required = false) PasskeyOptionsRequestDto optionsRequestDto,
                                                           @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                                           @RequestHeader(name = "X-MFA-Step-Id", required = false) String mfaStepIdHeader, // 클라이언트가 현재 stepId를 알면 전달
                                                           HttpServletRequest httpServletRequest) {
        // ... (FactorContext 로드 및 유효성 검사) ...
        FactorContext factorContext = contextPersistence.contextLoad(httpServletRequest);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader) ||
                !StringUtils.hasText(factorContext.getFlowTypeName())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID_OPTIONS", "MFA 세션이 유효하지 않거나 플로우 정보가 없습니다."));
        }
        if (optionsRequestDto != null && optionsRequestDto.username() != null && !Objects.equals(factorContext.getUsername(), optionsRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH_OPTIONS", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        // 상태 및 Factor 타입 검증 (AWAITING_FACTOR_CHALLENGE_INITIATION 또는 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
        if (factorContext.getCurrentProcessingFactor() != AuthType.PASSKEY ||
                !(factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                        factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) {
            log.warn("Passkey assertion options requested in invalid state ({}) or for non-Passkey factor ({}). Session ID: {}",
                    factorContext.getCurrentState(), factorContext.getCurrentProcessingFactor(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("INVALID_STATE_FOR_PASSKEY_OPTIONS_REQ", "잘못된 상태에서 Passkey 옵션 요청."));
        }
        // currentStepId는 MfaContinuationFilter에서 challenge UI 로드 시 설정되어야 함.
        if (!StringUtils.hasText(factorContext.getCurrentStepId())) {
            log.error("Passkey assertion options request but currentStepId is null in FactorContext. Session: {}", mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("MFA_CONTEXT_MISSING_STEPID", "MFA 컨텍스트에 현재 단계 정보가 없습니다."));
        }
        // 만약 클라이언트가 stepId를 보냈다면, FactorContext의 값과 일치하는지 확인 (선택적)
        if (StringUtils.hasText(mfaStepIdHeader) && !Objects.equals(mfaStepIdHeader, factorContext.getCurrentStepId())) {
            log.warn("MFA Step ID mismatch in Passkey options request. Header: {}, Context: {}. Session: {}",
                    mfaStepIdHeader, factorContext.getCurrentStepId(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("MFA_STEP_ID_MISMATCH", "MFA 단계 정보가 일치하지 않습니다."));
        }


        // 실제 구현: Spring Security WebAuthn 컴포넌트 사용
        try {
            // String rpId = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");
            // RelyingPartyRegistration relyingParty = relyingPartyRepository.findByRpId(rpId);
            // if (relyingParty == null) throw new IllegalStateException("RP not found for " + rpId);
            // PublicKeyCredentialRequestOptions assertionOptions = assertionOptionsChallengeGenerator.generate(
            // relyingParty, WebAuthnAuthenticationRequest.builder(factorContext.getUsername()).build()
            // );
            // return ResponseEntity.ok(assertionOptions.toMap()); // PublicKeyCredentialRequestOptions를 Map으로 변환 또는 직접 JSON 직렬화

            // 임시 로직 (실제로는 스프링 시큐리티 WebAuthn 엔진 사용)
            String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(new SecureRandom().generateSeed(32));
            Map<String, Object> assertionOptionsMap = new HashMap<>();
            assertionOptionsMap.put("challenge", challenge);
            assertionOptionsMap.put("rpId", applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost"));
            // assertionOptionsMap.put("allowCredentials", ...); // WebAuthnCredentialRecordStore 사용
            assertionOptionsMap.put("userVerification", "preferred");
            assertionOptionsMap.put("timeout", authContextProperties.getMfa().getOtpTokenValiditySeconds() * 1000L); // 예시로 OTP 유효시간 사용

            log.info("MFA Passkey assertion options (temporary) generated for user {} (session {}, stepId {})",
                    factorContext.getUsername(), mfaSessionIdHeader, factorContext.getCurrentStepId());
            return ResponseEntity.ok(assertionOptionsMap);

        } catch (Exception e) {
            log.error("Error generating MFA Passkey assertion options for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(createErrorResponse("PASSKEY_OPTIONS_GENERATION_ERROR", "Passkey 옵션 생성에 실패했습니다: " + e.getMessage()));
        }
    }

    private Map<String, String> createErrorResponse(String errorCode, String message) {
        return Map.of("status", "ERROR", "errorCode", errorCode, "message", message);
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
        // PrimaryAuthenticationSuccessHandler의 것과 동일한 로직 사용
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);
            }
        } catch (Exception e) {
            log.warn("MfaApiController: Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }
    private Optional<AuthenticationStepConfig> findStepConfigByFactorTypeAndMinOrder(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        // PrimaryAuthenticationSuccessHandler의 것과 동일한 로직 사용
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    private record SelectFactorRequestDto(String factorType, @Nullable String username) {}
    private record OttCodeRequestDto(@Nullable String username) {} // username은 FactorContext에서 가져오므로 API 요청 시에는 불필요할 수 있음
    private record PasskeyOptionsRequestDto(@Nullable String username) {}
}