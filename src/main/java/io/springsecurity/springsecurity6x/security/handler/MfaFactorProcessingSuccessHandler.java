package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 완전 일원화된 MfaFactorProcessingSuccessHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine에서 직접 컨텍스트 로드 및 관리
 */
@Slf4j
public class MfaFactorProcessingSuccessHandler implements AuthenticationSuccessHandler {

    // ContextPersistence 완전 제거
    private final MfaPolicyProvider mfaPolicyProvider;
    private final UnifiedAuthenticationSuccessHandler finalSuccessHandler;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public MfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator, // ContextPersistence 대신 사용
                                             MfaPolicyProvider mfaPolicyProvider,
                                             UnifiedAuthenticationSuccessHandler finalSuccessHandler,
                                             AuthResponseWriter responseWriter,
                                             ApplicationContext applicationContext,
                                             AuthContextProperties authContextProperties) {
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.finalSuccessHandler = finalSuccessHandler;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.authContextProperties = authContextProperties;
        this.stateMachineIntegrator = mfaStateMachineIntegrator;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MFA Factor successfully processed for user: {} via unified State Machine",
                authentication.getName());

        // 완전 일원화: State Machine에서만 FactorContext 로드
        FactorContext factorContext = loadFactorContextFromStateMachine(request);
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

        // State Machine에만 저장 (일원화)
        stateMachineIntegrator.saveFactorContext(factorContext);

        // 다음 MFA 단계 결정
        mfaPolicyProvider.determineNextFactorToProcess(factorContext);

        // 최신 상태 동기화 - State Machine 에서 다시 로드
        FactorContext latestContext = stateMachineIntegrator.loadFactorContext(factorContext.getMfaSessionId());
        if (latestContext != null) {
            syncContextFromStateMachine(factorContext, latestContext);
        }

        if (factorContext.isCompleted()) {
            log.info("All MFA factors completed for user: {}. Proceeding to final authentication success.",
                    factorContext.getUsername());

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

            Map<String, Object> responseBody = createMfaContinueResponse(
                    "다음 인증 단계로 진행합니다: " + nextFactorType.name(),
                    factorContext,
                    nextUiPageUrl
            );
            responseBody.put("nextFactorType", nextFactorType.name());
            responseBody.put("nextStepId", nextStepId);

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MFA factor {} completed for user {}. Proceeding to factor selection page.",
                    currentFactorType, factorContext.getUsername());

            Map<String, Object> responseBody = createMfaContinueResponse(
                    "다음 인증 수단을 선택해주세요.",
                    factorContext,
                    request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl()
            );
            responseBody.put("availableFactors", factorContext.getRegisteredMfaFactors());

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else {
            log.error("Unexpected FactorContext state ({}) after processing factor {} for user {}.",
                    factorContext.getCurrentState(), currentFactorType, factorContext.getUsername());
            handleGenericError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    /**
     * 완전 일원화: State Machine에서만 FactorContext 로드
     */
    private FactorContext loadFactorContextFromStateMachine(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in session. Cannot load FactorContext.");
            return null;
        }

        try {
            // State Machine에서 직접 로드 (일원화)
            return stateMachineIntegrator.loadFactorContext(mfaSessionId);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from State Machine for session: {}", mfaSessionId, e);
            return null;
        }
    }

    /**
     * MFA 계속 진행 응답 생성 (공통 로직)
     */
    private Map<String, Object> createMfaContinueResponse(String message, FactorContext factorContext, String nextStepUrl) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "MFA_CONTINUE");
        responseBody.put("message", message);
        responseBody.put("nextStepUrl", nextStepUrl);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());

        // State Machine 정보
        Map<String, Object> stateMachineInfo = new HashMap<>();
        stateMachineInfo.put("currentState", factorContext.getCurrentState().name());
        stateMachineInfo.put("sessionId", factorContext.getMfaSessionId());
        stateMachineInfo.put("storageType", "UNIFIED_STATE_MACHINE");

        responseBody.put("stateMachine", stateMachineInfo);
        return responseBody;
    }

    /**
     * State Machine에서 컨텍스트 동기화
     */
    private void syncContextFromStateMachine(FactorContext target, FactorContext source) {
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setCurrentFactorOptions(source.getCurrentFactorOptions());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        log.debug("Context synchronized from unified State Machine: sessionId={}, version={}, state={}",
                target.getMfaSessionId(), target.getVersion(), target.getCurrentState());
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
                                      String errorCode, String logMessage, @Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success: Invalid FactorContext. Message: {}. User from auth: {}",
                logMessage, (authentication != null ? authentication.getName() : "UnknownUser"));

        // 세션에서 잘못된 MFA 세션 ID 정리
        HttpSession session = request.getSession(false);
        if (session != null) {
            String oldSessionId = (String) session.getAttribute("MFA_SESSION_ID");
            if (oldSessionId != null) {
                try {
                    stateMachineIntegrator.releaseStateMachine(oldSessionId);
                } catch (Exception e) {
                    log.warn("Failed to release invalid State Machine session: {}", oldSessionId, e);
                }
                session.removeAttribute("MFA_SESSION_ID");
            }
        }

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI());
    }

    private void handleConfigError(HttpServletResponse response, HttpServletRequest request,
                                   FactorContext ctx, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", ctx.getFlowTypeName(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_FLOW_CONFIG_ERROR", message, request.getRequestURI());

        // State Machine 정리
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
        } catch (Exception e) {
            log.warn("Failed to release State Machine session after config error: {}", ctx.getMfaSessionId(), e);
        }
    }

    private void handleGenericError(HttpServletResponse response, HttpServletRequest request,
                                    FactorContext ctx, String message) throws IOException {
        log.error("Generic error during MFA factor processing for user {}: {}", ctx.getUsername(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", message, request.getRequestURI());

        // State Machine 정리
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
        } catch (Exception e) {
            log.warn("Failed to release State Machine session after generic error: {}", ctx.getMfaSessionId(), e);
        }
    }
}