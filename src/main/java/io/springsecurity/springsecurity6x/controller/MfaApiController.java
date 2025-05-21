package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService; // EmailOneTimeTokenService 는 이제 MfaContinuationFilter -> GenerateOneTimeTokenFilter 에서 사용됨
import jakarta.servlet.http.HttpServletRequest;
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
    // private final EmailOneTimeTokenService emailOttService; // MfaApiController에서 직접 사용하지 않음

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

        // int lastCompletedOrder = factorContext.getLastCompletedFactorOrder(); // 이 메서드가 FactorContext에 없다고 가정하고 주석 처리
        // 대신, MfaPolicyProvider가 다음 단계를 결정하거나, FactorContext의 completedFactors를 기반으로 결정할 수 있음.
        // 여기서는 가장 첫 번째로 매칭되는 factor를 선택하도록 단순화 (또는 MfaPolicyProvider에 위임 필요)
//        int lastCompletedOrder = factorContext.getLastCompletedFactorOrderIfAvailable(); // FactorContext에 해당 메서드가 있다고 가정하고 호출, 없다면 0을 반환하도록 FactorContext 수정 필요
        int lastCompletedOrder = 1; // FactorContext에 해당 메서드가 있다고 가정하고 호출, 없다면 0을 반환하도록 FactorContext 수정 필요

        Optional<AuthenticationStepConfig> selectedStepOpt = findStepConfigByFactorTypeAndMinOrder(currentFlowConfig, selectedFactorType, lastCompletedOrder);

        if (selectedStepOpt.isEmpty()) {
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
            // MfaContinuationFilter가 이 URL을 받아서 코드 생성 필터로 연결
            nextUiPageUrl = request.getContextPath() + authContextProperties.getOttFactor().getRequestCodeUiUrl(); // 예: /mfa/ott/request-code-ui
        } else if (selectedFactorType == AuthType.PASSKEY) {
            nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl(); // 예: /mfa/challenge/passkey
        } else {
            log.warn("No specific UI page defined for selected MFA factor: {}", selectedFactorType);
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

    // 이 API 엔드포인트는 더 이상 직접적인 코드 생성/발송을 담당하지 않습니다.
    // 코드 생성은 MfaContinuationFilter를 통해 GenerateOneTimeTokenFilter로 위임됩니다.
    // 필요하다면 이 엔드포인트는 코드 '재전송' 기능으로 역할을 변경하거나, 다른 용도로 사용될 수 있습니다.
    // 현재는 주석 처리하여 사용하지 않도록 합니다.
    /*
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
        if (ottRequestDto != null && StringUtils.hasText(ottRequestDto.username()) && !Objects.equals(factorContext.getUsername(), ottRequestDto.username())) {
            log.warn("MFA OTT code request: Username in DTO ({}) does not match FactorContext username ({}). Using FactorContext username.",
                    ottRequestDto.username(), factorContext.getUsername());
        }

        if (factorContext.getCurrentProcessingFactor() != AuthType.OTT ||
                !(factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                  factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) {
            log.warn("OTT code request in invalid state ({}) or for non-OTT factor ({}). Session ID: {}",
                    factorContext.getCurrentState(), factorContext.getCurrentProcessingFactor(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("INVALID_STATE_FOR_OTT_REQUEST", "잘못된 상태에서 OTT 코드 요청입니다."));
        }

        // EmailOneTimeTokenService는 Spring Security Filter Chain 내에서 호출되도록 변경
        // try {
        //     emailOttService.generateAndSendVerificationCode(factorContext.getUsername(), "MFA Authentication");
        //     log.info("MFA OTT code requested and sent to {} for session {}", factorContext.getUsername(), mfaSessionIdHeader);
        //
        //     String nextStepUrl = request.getContextPath() + authContextProperties.getOttFactor().getChallengeUrl();
        //
        //     Map<String, Object> responseBody = new HashMap<>();
        //     responseBody.put("status", "MFA_OTT_CODE_SENT");
        //     responseBody.put("message", "새로운 인증 코드가 " + factorContext.getUsername() + "(으)로 발송되었습니다. 확인 후 입력해주세요.");
        //     responseBody.put("nextStepUrl", nextStepUrl);
        //
        //     return ResponseEntity.ok(responseBody);
        // } catch (Exception e) {
        //     log.error("Error requesting/sending MFA OTT code for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
        //     return ResponseEntity.internalServerError().body(createErrorResponse("OTT_REQUEST_FAILED", "인증 코드 요청/발송에 실패했습니다: " + e.getMessage()));
        // }
        log.warn("/api/mfa/request-ott-code endpoint is deprecated. OTT code generation should be handled by MfaContinuationFilter redirecting to a generation URL.");
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(createErrorResponse("ENDPOINT_DEPRECATED", "This endpoint is no longer used for direct code generation."));
    }
    */

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
        if (optionsRequestDto != null && optionsRequestDto.username() != null && !Objects.equals(factorContext.getUsername(), optionsRequestDto.username())) {
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
        if (StringUtils.hasText(mfaStepIdHeader) && !Objects.equals(mfaStepIdHeader, factorContext.getCurrentStepId())) {
            log.warn("MFA Step ID mismatch in Passkey options request. Header: {}, Context: {}. Session: {}",
                    mfaStepIdHeader, factorContext.getCurrentStepId(), mfaSessionIdHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(createErrorResponse("MFA_STEP_ID_MISMATCH", "MFA 단계 정보가 일치하지 않습니다."));
        }

        try {
            String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(new SecureRandom().generateSeed(32));

            // FactorContext에 challenge를 저장하는 로직은 FactorContext 클래스의 실제 구현에 따라 달라집니다.
            // factorContext.setChallenge(challenge); // 이 라인은 FactorContext에 setChallenge 메서드가 없다면 오류 발생.
            // Passkey Challenge는 세션이나 WebAuthnChallengeRepository를 통해 관리하는 것이 일반적입니다.
            // 임시로 세션에 저장하는 예시 (실제 구현 시 변경 필요)
            httpServletRequest.getSession().setAttribute("PASSKEY_CHALLENGE_" + factorContext.getMfaSessionId(), challenge);
            log.info("Generated and stored Passkey challenge in session: {}", challenge);


            Map<String, Object> assertionOptionsMap = new HashMap<>();
            assertionOptionsMap.put("challenge", challenge);
            assertionOptionsMap.put("rpId", applicationContext.getEnvironment().getProperty("spring.security.webauthn.relying-party-id", "localhost"));
            assertionOptionsMap.put("userVerification", "preferred");
            assertionOptionsMap.put("timeout", authContextProperties.getMfa().getPasskeyFactor().getTimeoutSeconds() * 1000L);
            // TODO: allowCredentials는 실제 사용자의 등록된 credential ID 목록으로 채워야 합니다.
            // List<Map<String, Object>> allowedCredentials = ... ;
            // assertionOptionsMap.put("allowCredentials", allowedCredentials);

            log.info("MFA Passkey assertion options generated for user {} (session {}, stepId {})",
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

    // DTO 정의
    private record SelectFactorRequestDto(String factorType, @Nullable String username) {}
    private record OttCodeRequestDto(@Nullable String username) {}
    private record PasskeyOptionsRequestDto(@Nullable String username) {}
}