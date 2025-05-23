package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
// EmailOneTimeTokenService import는 더 이상 필요하지 않음
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa")
public class MfaApiController {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;

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

        // FactorContext.java에 정의된 getLastCompletedFactorOrder() 사용
        int lastCompletedOrder = factorContext.getLastCompletedFactorOrder();
        log.debug("Last completed factor order for user {}: {}", factorContext.getUsername(), lastCompletedOrder);

        Optional<AuthenticationStepConfig> selectedStepOpt = findStepConfigByFactorTypeAndMinOrder(currentFlowConfig, selectedFactorType, lastCompletedOrder);

        if (selectedStepOpt.isEmpty()) {
            log.error("No step config found for factor {} after order {} in flow {} for user {}", selectedFactorType, lastCompletedOrder, factorContext.getFlowTypeName(), factorContext.getUsername());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("MFA_STEP_CONFIG_MISSING", "선택한 인증 단계 설정을 찾을 수 없습니다."));
        }

        AuthenticationStepConfig selectedStep = selectedStepOpt.get();
        factorContext.setCurrentProcessingFactor(selectedFactorType);
        factorContext.setCurrentStepId(selectedStep.getStepId());
        if (currentFlowConfig.getRegisteredFactorOptions() != null) {
            factorContext.setCurrentFactorOptions(currentFlowConfig.getRegisteredFactorOptions().get(selectedFactorType));
        }
        factorContext.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        contextPersistence.saveContext(factorContext, request);

        String nextUiPageUrl;
        if (selectedFactorType == AuthType.OTT) {
            // OTT 코드 요청 UI로 리다이렉션. 이 UI에서 폼을 통해 코드 생성 요청.
            nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
        } else if (selectedFactorType == AuthType.PASSKEY) {
            // Passkey 챌린지 UI로 리다이렉션
            nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
        } else {
            log.warn("No specific UI page defined for selected MFA factor: {}. Defaulting path.", selectedFactorType);
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

    /*
     * MFA OTT 코드 생성/발송은 MfaContinuationFilter 와 GenerateOneTimeTokenFilter를 통해 처리됩니다.
     * 이 API 엔드포인트는 더 이상 직접적인 코드 생성에 사용되지 않습니다.
     * 클라이언트는 /mfa/ott/request-code-ui 페이지의 폼을 통해
     * authContextProperties.getOttFactor().getCodeGenerationUrl() 경로로 POST 요청을 보내야 합니다.
     */
    // @PostMapping("/request-ott-code")
    // public ResponseEntity<?> requestMfaOttCode(@RequestBody OttCodeRequestDto ottRequestDto,
    //                                            @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
    //                                            HttpServletRequest request) {
    //     log.warn("/api/mfa/request-ott-code endpoint is deprecated for initial code generation. " +
    //              "Use form submission from the OTT request UI to the configured codeGenerationUrl.");
    //
    //     FactorContext factorContext = contextPersistence.contextLoad(request);
    //     if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader)) {
    //         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다."));
    //     }
    //
    //     // 코드 "재전송" 로직이 필요하다면 여기에 구현할 수 있으나,
    //     // 일관성을 위해 재전송도 사용자가 UI에서 다시 폼을 제출하는 방식을 권장합니다.
    //     // (즉, /mfa/ott/request-code-ui 페이지로 다시 가서 '코드 발송' 버튼을 누르는 방식)
    //
    //     return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
    //                          .body(createErrorResponse("ENDPOINT_DEPRECATED",
    //                                  "OTT code generation is handled via form submission to Spring Security filters."));
    // }


    @PostMapping("/assertion/options")
    public ResponseEntity<?> getMfaPasskeyAssertionOptions(@RequestBody(required = false) PasskeyOptionsRequestDto optionsRequestDto,
                                                           @RequestHeader(name = "X-MFA-Session-Id", required = true) String mfaSessionIdHeader,
                                                           @RequestHeader(name = "X-MFA-Step-Id", required = false) String mfaStepIdHeader,
                                                           HttpServletRequest httpServletRequest) {
        FactorContext factorContext = contextPersistence.contextLoad(httpServletRequest);
        if (factorContext == null || !Objects.equals(factorContext.getMfaSessionId(), mfaSessionIdHeader) ||
                !StringUtils.hasText(factorContext.getFlowTypeName())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("MFA_SESSION_INVALID_OPTIONS", "MFA 세션이 유효하지 않거나 플로우 정보가 없습니다."));
        }
        if (optionsRequestDto != null && StringUtils.hasText(optionsRequestDto.username()) && !Objects.equals(factorContext.getUsername(), optionsRequestDto.username())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse("USER_MISMATCH_OPTIONS", "MFA 세션 사용자와 요청 사용자가 일치하지 않습니다."));
        }

        if (factorContext.getCurrentProcessingFactor() != AuthType.PASSKEY ||
                !(factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                        factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) {
            log.warn("Passkey assertion options requested in invalid state ({}) or for non-Passkey factor ({}). Session ID: {}",
                    factorContext.getCurrentState(), factorContext.getCurrentProcessingFactor(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("INVALID_STATE_FOR_PASSKEY_OPTIONS_REQ", "잘못된 상태에서 Passkey 옵션 요청."));
        }
        if (!StringUtils.hasText(factorContext.getCurrentStepId())) {
            log.error("Passkey assertion options request but currentStepId is null in FactorContext. Session: {}", mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("MFA_CONTEXT_MISSING_STEPID", "MFA 컨텍스트에 현재 단계 정보가 없습니다."));
        }
        // mfaStepIdHeader는 현재 사용되지 않음. FactorContext의 currentStepId를 신뢰.
        // if (StringUtils.hasText(mfaStepIdHeader) && !Objects.equals(mfaStepIdHeader, factorContext.getCurrentStepId())) { ... }

        try {
            SecureRandom random = new SecureRandom();
            byte[] challengeBytes = new byte[32];
            random.nextBytes(challengeBytes);
            String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

            // FactorContext에 setChallenge 메서드가 없으므로, HTTP 세션에 challenge 저장
            HttpSession session = httpServletRequest.getSession(false); // 기존 세션 가져오기
            if (session != null) {
                String sessionAttributeName = "PASSKEY_ASSERTION_CHALLENGE_" + factorContext.getMfaSessionId();
                session.setAttribute(sessionAttributeName, challenge);
                log.info("Passkey assertion challenge stored in session (attribute: {}) for MFA session ID: {}", sessionAttributeName, factorContext.getMfaSessionId());
            } else {
                // 세션이 없는 경우 에러 처리 또는 다른 저장 메커니즘 고려
                log.error("HttpSession not available to store Passkey challenge for MFA session ID: {}. Passkey assertion will likely fail.", factorContext.getMfaSessionId());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse("SESSION_UNAVAILABLE", "세션이 없어 Passkey 챌린지를 저장할 수 없습니다."));
            }

            Map<String, Object> assertionOptionsMap = new HashMap<>();
            assertionOptionsMap.put("challenge", challenge);
            assertionOptionsMap.put("rpId", applicationContext.getEnvironment().getProperty("spring.security.webauthn.relying-party-id", "localhost"));
            // TODO: allowCredentials는 실제 사용자의 등록된 credential ID 목록으로 채워야 함
            // 예: List<Map<String, Object>> allowedCredentials = webAuthnService.getAllowCredentials(factorContext.getUsername());
            // assertionOptionsMap.put("allowCredentials", allowedCredentials);
            assertionOptionsMap.put("userVerification", "preferred");
            assertionOptionsMap.put("timeout", authContextProperties.getMfa().getPasskeyFactor().getTimeoutSeconds() * 1000L);

            log.info("MFA Passkey assertion options generated for user {} (session {}, stepId {}).",
                    factorContext.getUsername(), mfaSessionIdHeader, factorContext.getCurrentStepId());
            return ResponseEntity.ok(assertionOptionsMap);

        } catch (Exception e) {
            log.error("Error generating MFA Passkey assertion options for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(createErrorResponse("PASSKEY_OPTIONS_GENERATION_ERROR", "Passkey 옵션 생성에 실패했습니다: " + e.getMessage()));
        }
    }

    private Map<String, String> createErrorResponse(String errorCode, String message) {
        Map<String, String> response = new LinkedHashMap<>();
        response.put("status", "ERROR");
        response.put("errorCode", errorCode);
        response.put("message", message);
        return response;
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
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
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    private record SelectFactorRequestDto(String factorType, @Nullable String username) {}
    // OttCodeRequestDto는 /api/mfa/request-ott-code가 제거되므로 사용되지 않음.
    // private record OttCodeRequestDto(@Nullable String username) {}
    private record PasskeyOptionsRequestDto(@Nullable String username) {}
}