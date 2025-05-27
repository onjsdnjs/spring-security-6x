package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
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

    private final MfaPolicyProvider mfaPolicyProvider;
    private final UnifiedAuthenticationSuccessHandler finalSuccessHandler;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;

    public MfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                             MfaPolicyProvider mfaPolicyProvider,
                                             UnifiedAuthenticationSuccessHandler finalSuccessHandler,
                                             AuthResponseWriter responseWriter,
                                             ApplicationContext applicationContext,
                                             AuthContextProperties authContextProperties,
                                             MfaSessionRepository sessionRepository) { // 추가
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.finalSuccessHandler = finalSuccessHandler;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.authContextProperties = authContextProperties;
        this.stateMachineIntegrator = mfaStateMachineIntegrator;
        this.sessionRepository = sessionRepository; // 추가
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MFA Factor successfully processed for user: {} using {} repository",
                authentication.getName(), sessionRepository.getRepositoryType());

        // 개선: Repository 패턴을 통한 FactorContext 로드 (HttpSession 직접 접근 제거)
        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            handleInvalidContext(response, request, "MFA_FACTOR_SUCCESS_NO_CONTEXT",
                    "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.", authentication);
            return;
        }

        // 개선: Repository를 통한 세션 검증
        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor processing success",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(response, request, factorContext);
            return;
        }

        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

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
        factorContext.resetFailedAttempts(currentStepId);

        // 개선: Repository를 통한 세션 갱신
        sessionRepository.refreshSession(factorContext.getMfaSessionId());

        stateMachineIntegrator.saveFactorContext(factorContext);
        mfaPolicyProvider.determineNextFactorToProcess(factorContext);

        FactorContext latestContext = stateMachineIntegrator.loadFactorContext(factorContext.getMfaSessionId());
        if (latestContext != null) {
            syncContextFromStateMachine(factorContext, latestContext);
        }

        if (factorContext.isCompleted()) {
            log.info("All MFA factors completed for user: {} using {} repository. Proceeding to final authentication success.",
                    factorContext.getUsername(), sessionRepository.getRepositoryType());

            finalSuccessHandler.onAuthenticationSuccess(request, response,
                    factorContext.getPrimaryAuthentication());

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null &&
                StringUtils.hasText(factorContext.getCurrentStepId())) {

            AuthType nextFactorType = factorContext.getCurrentProcessingFactor();
            String nextStepId = factorContext.getCurrentStepId();

            log.info("MFA factor {} completed for user {} using {} repository. Proceeding to next factor: {}",
                    currentFactorType, factorContext.getUsername(), sessionRepository.getRepositoryType(), nextFactorType);

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
            log.info("MFA factor {} completed for user {} using {} repository. Proceeding to factor selection page.",
                    currentFactorType, factorContext.getUsername(), sessionRepository.getRepositoryType());

            Map<String, Object> responseBody = createMfaContinueResponse(
                    "다음 인증 수단을 선택해주세요.",
                    factorContext,
                    request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl()
            );
            responseBody.put("availableFactors", factorContext.getRegisteredMfaFactors());

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else {
            log.error("Unexpected FactorContext state ({}) after processing factor {} for user {} using {} repository.",
                    factorContext.getCurrentState(), currentFactorType, factorContext.getUsername(),
                    sessionRepository.getRepositoryType());
            handleGenericError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    /**
     * 개선: Repository 정보를 포함한 MFA 계속 진행 응답 생성
     */
    private Map<String, Object> createMfaContinueResponse(String message, FactorContext factorContext, String nextStepUrl) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "MFA_CONTINUE");
        responseBody.put("message", message);
        responseBody.put("nextStepUrl", nextStepUrl);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());

        // 개선: Repository 정보 추가
        Map<String, Object> sessionInfo = new HashMap<>();
        sessionInfo.put("currentState", factorContext.getCurrentState().name());
        sessionInfo.put("sessionId", factorContext.getMfaSessionId());
        sessionInfo.put("repositoryType", sessionRepository.getRepositoryType());
        sessionInfo.put("distributedSync", sessionRepository.supportsDistributedSync());

        responseBody.put("sessionInfo", sessionInfo);
        return responseBody;
    }

    /**
     * 개선: Repository 패턴을 통한 세션 미발견 처리
     */
    private void handleSessionNotFound(HttpServletResponse response, HttpServletRequest request,
                                       FactorContext factorContext) throws IOException {
        log.warn("Session not found in {} repository during factor processing success: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType());
        errorResponse.put("mfaSessionId", factorContext.getMfaSessionId());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.", request.getRequestURI(), errorResponse);
    }

    /**
     * 개선: Repository 패턴을 통한 무효한 컨텍스트 처리 (HttpSession 직접 접근 제거)
     */
    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage, @Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success using {} repository: Invalid FactorContext. Message: {}. User from auth: {}",
                sessionRepository.getRepositoryType(), logMessage,
                (authentication != null ? authentication.getName() : "UnknownUser"));

        // 개선: Repository를 통한 세션 정리 (HttpSession 직접 접근 제거)
        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, null);
            } catch (Exception e) {
                log.warn("Failed to release invalid session using {} repository: {}",
                        sessionRepository.getRepositoryType(), oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType()); // 추가

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI(), errorResponse);
    }

    /**
     * State Machine 에서 컨텍스트 동기화
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