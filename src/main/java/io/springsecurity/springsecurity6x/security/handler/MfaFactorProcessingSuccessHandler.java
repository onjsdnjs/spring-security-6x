package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.FilterChain;
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
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class MfaFactorProcessingSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final UnifiedAuthenticationSuccessHandler finalSuccessHandler;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public MfaFactorProcessingSuccessHandler(ContextPersistence contextPersistence,
                                             MfaPolicyProvider mfaPolicyProvider,
                                             UnifiedAuthenticationSuccessHandler finalSuccessHandler,
                                             AuthResponseWriter responseWriter,
                                             ApplicationContext applicationContext,
                                             AuthContextProperties authContextProperties) {
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.finalSuccessHandler = finalSuccessHandler;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.authContextProperties = authContextProperties;

        // State Machine 통합자 초기화
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MFA Factor successfully processed for user: {}", authentication.getName());

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            handleInvalidContext(response, request, "MFA_FACTOR_SUCCESS_NO_CONTEXT",
                    "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.", authentication);
            return;
        }

        // State Machine과 동기화
        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        // FACTOR_VERIFIED_SUCCESS 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(
                MfaEvent.FACTOR_VERIFIED_SUCCESS, factorContext, request);

        if (!accepted) {
            log.error("State Machine rejected FACTOR_VERIFIED_SUCCESS event for session: {}",
                    factorContext.getMfaSessionId());
            handleStateTransitionError(response, request, factorContext);
            return;
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
        if (mfaFlowConfig == null) {
            handleConfigError(response, request, factorContext,
                    "MFA 플로우 설정을 찾을 수 없습니다: " + factorContext.getFlowTypeName());
            return;
        }

        AuthType currentFactorType = factorContext.getCurrentProcessingFactor();
        String currentStepId = factorContext.getCurrentStepId();

        if (currentFactorType == null || !StringUtils.hasText(currentStepId)) {
            handleInvalidContext(response, request, "MFA_FACTOR_SUCCESS_MISSING_CURRENT_FACTOR_INFO",
                    "MFA 팩터 처리 성공 후 현재 팩터 정보를 찾을 수 없습니다.", authentication);
            return;
        }

        // 현재 완료된 AuthenticationStepConfig 찾기
        Optional<AuthenticationStepConfig> currentStepConfigOpt = mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> currentStepId.equals(step.getStepId()) &&
                        currentFactorType.name().equalsIgnoreCase(step.getType()))
                .findFirst();

        if (currentStepConfigOpt.isEmpty()) {
            handleConfigError(response, request, factorContext,
                    "현재 처리된 MFA 단계에 대한 설정을 찾을 수 없습니다.");
            return;
        }

        AuthenticationStepConfig currentFactorJustCompleted = currentStepConfigOpt.get();
        factorContext.addCompletedFactor(currentFactorJustCompleted);

        // 실패 횟수 초기화
        factorContext.resetFailedAttempts(currentStepId);

        // 다음 MFA 단계 결정
        mfaPolicyProvider.determineNextFactorToProcess(factorContext);

        // State Machine과 동기화 후 저장
        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);
        contextPersistence.saveContext(factorContext, request);

        if (factorContext.isCompleted()) {
            log.info("All MFA factors completed for user: {}. Proceeding to final authentication success.",
                    factorContext.getUsername());

            // ALL_REQUIRED_FACTORS_COMPLETED 이벤트는 이미 DefaultMfaPolicyProvider에서 전송됨
            // 최종 성공 핸들러로 위임
            finalSuccessHandler.onAuthenticationSuccess(request, response,
                    factorContext.getPrimaryAuthentication());

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null &&
                StringUtils.hasText(factorContext.getCurrentStepId())) {

            AuthType nextFactorType = factorContext.getCurrentProcessingFactor();
            String nextStepId = factorContext.getCurrentStepId();

            log.info("MFA factor {} completed for user {}. Proceeding to next factor: {}",
                    currentFactorType, factorContext.getUsername(), nextFactorType);

            String nextUiPageUrl = determineNextFactorUrl(nextFactorType, request);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "MFA_CONTINUE");
            responseBody.put("message", "다음 인증 단계로 진행합니다: " + nextFactorType.name());
            responseBody.put("nextFactorType", nextFactorType.name());
            responseBody.put("nextStepId", nextStepId);
            responseBody.put("nextStepUrl", nextUiPageUrl);
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
            responseBody.put("stateMachine", Map.of(
                    "currentState", factorContext.getCurrentState().name(),
                    "sessionId", factorContext.getMfaSessionId()
            ));

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MFA factor {} completed for user {}. Proceeding to factor selection page.",
                    currentFactorType, factorContext.getUsername());

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "MFA_CONTINUE");
            responseBody.put("message", "다음 인증 수단을 선택해주세요.");
            responseBody.put("nextStepUrl", request.getContextPath() +
                    authContextProperties.getMfa().getSelectFactorUrl());
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
            responseBody.put("stateMachine", Map.of(
                    "currentState", factorContext.getCurrentState().name(),
                    "sessionId", factorContext.getMfaSessionId(),
                    "availableFactors", factorContext.getRegisteredMfaFactors()
            ));

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else {
            log.error("Unexpected FactorContext state ({}) after processing factor {} for user {}.",
                    factorContext.getCurrentState(), currentFactorType, factorContext.getUsername());
            handleGenericError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    private String determineNextFactorUrl(AuthType factorType, HttpServletRequest request) {
        return switch (factorType) {
            case OTT -> request.getContextPath() +
                    authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            case PASSKEY -> request.getContextPath() +
                    authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            default -> {
                log.error("Unsupported MFA factor type: {}", factorType);
                yield request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
            }
        };
    }

    private void handleStateTransitionError(HttpServletResponse response, HttpServletRequest request,
                                            FactorContext ctx) throws IOException {
        log.error("State Machine transition error for session: {}", ctx.getMfaSessionId());

        // SYSTEM_ERROR 이벤트 전송
        stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, request);

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "STATE_TRANSITION_ERROR", "상태 전이 오류가 발생했습니다.",
                request.getRequestURI());
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {
        if (!StringUtils.hasText(flowTypeName)) {
            return null;
        }

        PlatformConfig platformConfig;
        try {
            platformConfig = applicationContext.getBean(PlatformConfig.class);
        } catch (Exception e) {
            log.error("PlatformConfig bean not found in ApplicationContext", e);
            return null;
        }

        if (platformConfig == null || platformConfig.getFlows() == null) {
            log.error("PlatformConfig or its flows list is null");
            return null;
        }

        List<AuthenticationFlowConfig> matchingFlows = platformConfig.getFlows().stream()
                .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                .collect(Collectors.toList());

        if (matchingFlows.isEmpty()) {
            log.warn("No AuthenticationFlowConfig found with typeName '{}'", flowTypeName);
            return null;
        }

        if (matchingFlows.size() > 1) {
            log.error("CRITICAL: Multiple AuthenticationFlowConfigs found for typeName '{}'. Using first one.",
                    flowTypeName);
        }

        return matchingFlows.get(0);
    }

    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage,@Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success: Invalid FactorContext. Message: {}. User from auth: {}",
                logMessage, (authentication != null ? authentication.getName() : "UnknownUser"));
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI());
        FactorContext existingCtx = contextPersistence.contextLoad(request);
        if (existingCtx != null) contextPersistence.deleteContext(request);
    }

    private void handleConfigError(HttpServletResponse response, HttpServletRequest request,
                                   FactorContext ctx, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", ctx.getFlowTypeName(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_FLOW_CONFIG_ERROR", message, request.getRequestURI());
        contextPersistence.deleteContext(request);
    }

    private void handleGenericError(HttpServletResponse response, HttpServletRequest request,
                                    FactorContext ctx, String message) throws IOException {
        log.error("Generic error during MFA factor processing for user {}: {}", ctx.getUsername(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", message, request.getRequestURI());
        contextPersistence.deleteContext(request);
    }
}