package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class MfaFactorProcessingSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final UnifiedAuthenticationSuccessHandler finalSuccessHandler;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.debug("MFA Factor successfully processed for user: {}", authentication.getName());

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            handleInvalidContext(response, request, "MFA_FACTOR_SUCCESS_NO_CONTEXT", "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.", authentication);
            return;
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
        if (mfaFlowConfig == null) {
            handleConfigError(response, request, factorContext, "MFA 플로우 설정을 찾을 수 없습니다: " + factorContext.getFlowTypeName());
            return;
        }

        AuthType currentFactorType = factorContext.getCurrentProcessingFactor();
        String currentStepId = factorContext.getCurrentStepId();

        if (currentFactorType == null || !StringUtils.hasText(currentStepId)) {
            handleInvalidContext(response, request, "MFA_FACTOR_SUCCESS_MISSING_CURRENT_FACTOR_INFO", "MFA 팩터 처리 성공 후 현재 팩터 정보를 찾을 수 없습니다.", authentication);
            return;
        }

        // 현재 완료된 AuthenticationStepConfig 찾기
        Optional<AuthenticationStepConfig> currentStepConfigOpt = mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> currentStepId.equals(step.getStepId()) && currentFactorType.name().equalsIgnoreCase(step.getType()))
                .findFirst();

        if (currentStepConfigOpt.isEmpty()) {
            handleConfigError(response, request, factorContext, "현재 처리된 MFA 단계 (" + currentStepId + ", " + currentFactorType + ")에 대한 설정을 찾을 수 없습니다.");
            return;
        }
        AuthenticationStepConfig currentFactorJustCompleted = currentStepConfigOpt.get();
        factorContext.addCompletedFactor(currentFactorJustCompleted); // *** 수정된 부분: AuthenticationStepConfig 객체 전달 ***

        // 실패 횟수 초기화 (해당 팩터에 대해)
        factorContext.resetFailedAttempts(currentStepId);
        // 또는 factorContext.resetFailedAttempts(currentFactorType.name());

        // 다음 MFA 단계 결정
        mfaPolicyProvider.determineNextFactorToProcess(factorContext);
        contextPersistence.saveContext(factorContext, request);

        if (factorContext.isCompleted()) {
            log.info("All MFA factors completed for user: {}. Proceeding to final authentication success.", factorContext.getUsername());
            // factorContext.changeState(MfaState.MFA_COMPLETED); // MfaPolicyProvider가 이미 MFA_COMPLETED로 설정했을 것임
            // contextPersistence.saveContext(factorContext, request); // 위에서 이미 저장됨
            finalSuccessHandler.onAuthenticationSuccess(request, response, factorContext.getPrimaryAuthentication());
        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null &&
                StringUtils.hasText(factorContext.getCurrentStepId())) {

            AuthType nextFactorType = factorContext.getCurrentProcessingFactor();
            String nextStepId = factorContext.getCurrentStepId();
            log.info("MFA factor {} (stepId: {}) completed for user {}. Proceeding to next factor: {} (stepId: {})",
                    currentFactorType, currentStepId, factorContext.getUsername(), nextFactorType, nextStepId);

            String nextUiPageUrl;
            if (nextFactorType == AuthType.OTT) {
                nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            } else if (nextFactorType == AuthType.PASSKEY) {
                nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            } else {
                log.error("Unsupported next MFA factor type: {}. Cannot determine nextStepUrl for user: {}", nextFactorType, factorContext.getUsername());
                handleGenericError(response, request, factorContext, "지원하지 않는 다음 MFA 인증 수단입니다.");
                return;
            }

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "MFA_CONTINUE");
            responseBody.put("message", "다음 인증 단계로 진행합니다: " + nextFactorType.name());
            responseBody.put("nextFactorType", nextFactorType.name());
            responseBody.put("nextStepId", nextStepId);
            responseBody.put("nextStepUrl", nextUiPageUrl);
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MFA factor {} (stepId: {}) completed for user {}. Proceeding to factor selection page.",
                    currentFactorType, currentStepId, factorContext.getUsername());
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "MFA_CONTINUE");
            responseBody.put("message", "다음 인증 수단을 선택해주세요.");
            responseBody.put("nextStepUrl", request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl());
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        } else {
            log.error("MFA Factor Processing Success: Unexpected FactorContext state ({}) after processing factor {} for user {}.",
                    factorContext.getCurrentState(), currentFactorType, factorContext.getUsername());
            handleGenericError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {
        if (!StringUtils.hasText(flowTypeName)) return null;
        if (!AuthType.MFA.name().equalsIgnoreCase(flowTypeName)) { // MFA 플로우만 처리
            log.warn("Attempting to find non-MFA flow config in MfaFactorProcessingSuccessHandler: {}", flowTypeName);
            return null;
        }
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);
            }
        } catch (Exception e) {
            log.warn("Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request, String errorCode, String logMessage, @Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success: Invalid FactorContext. Message: {}. User from auth: {}", logMessage, (authentication != null ? authentication.getName() : "UnknownUser"));
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode, "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI());
        FactorContext existingCtx = contextPersistence.contextLoad(request);
        if (existingCtx != null) contextPersistence.deleteContext(request);
    }
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request, FactorContext ctx, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", ctx.getFlowTypeName(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_FLOW_CONFIG_ERROR", message, request.getRequestURI());
        contextPersistence.deleteContext(request);
    }
    private void handleGenericError(HttpServletResponse response, HttpServletRequest request, FactorContext ctx, String message) throws IOException {
        log.error("Generic error during MFA factor processing for user {}: {}", ctx.getUsername(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_PROCESSING_ERROR", message, request.getRequestURI());
        contextPersistence.deleteContext(request);
    }
}