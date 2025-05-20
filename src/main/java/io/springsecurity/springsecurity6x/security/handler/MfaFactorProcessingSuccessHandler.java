package io.springsecurity.springsecurity6x.security.handler;

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
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class MfaFactorProcessingSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;
    private final ApplicationContext applicationContext;
    private final UnifiedAuthenticationSuccessHandler finalTokenIssuingHandler;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MfaFactorProcessingSuccessHandler: Factor authentication success for user: {}", authentication.getName());
        processFactorSuccess(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || !Objects.equals(authentication.getName(), token.getUsername())) {
            log.warn("MfaFactorProcessingSuccessHandler (OTT): Auth mismatch or not found after OTT Factor. OTT User: {}, Auth User: {}",
                    token.getUsername(), (authentication != null ? authentication.getName() : "N/A"));
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "OTT_FACTOR_AUTH_CONTEXT_ERROR", "OTT 인증 요소 처리 후 사용자 컨텍스트 오류.", request.getRequestURI());
            return;
        }
        log.debug("MfaFactorProcessingSuccessHandler (OTT): Factor success for user: {} via OTT for: {}",
                authentication.getName(), token.getUsername());
        processFactorSuccess(request, response, authentication);
    }

    private void processFactorSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            handleContextError(response, request, authentication, "FactorContext is null or username mismatch.");
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        if (currentFactorJustCompleted == null) {
            handleContextError(response, request, authentication, "currentProcessingFactor is null in FactorContext.");
            return;
        }
        String currentCompletedStepId = factorContext.getCurrentStepId(); // 현재 완료된 stepId
        if (!StringUtils.hasText(currentCompletedStepId)){
            handleContextError(response, request, authentication, "currentStepId is null in FactorContext.");
            return;
        }


        log.info("MFA Factor Success: Factor {} (stepId: {}) for user {} (session {}) completed.",
                currentFactorJustCompleted, currentCompletedStepId, factorContext.getUsername(), factorContext.getMfaSessionId());

        factorContext.addCompletedFactor(currentFactorJustCompleted);

        AuthenticationFlowConfig currentFlowConfig = findFlowConfigByName(factorContext.getFlowTypeName());
        if (currentFlowConfig == null) {
            handleConfigError(response, request, factorContext.getFlowTypeName(), "MFA 플로우 설정을 찾을 수 없습니다.");
            return;
        }

        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactorToProcess(factorContext);
        Map<String, Object> responseBody = new HashMap<>();

        if (nextFactorToProcess != null) {
            // 다음 Factor에 대한 AuthenticationStepConfig 찾기
            int currentOrder = getStepOrder(currentFlowConfig, currentCompletedStepId);
            Optional<AuthenticationStepConfig> nextStepOpt = findStepConfigByFactorTypeAndMinOrder(currentFlowConfig, nextFactorToProcess, currentOrder);

            if (nextStepOpt.isPresent()) {
                AuthenticationStepConfig nextStep = nextStepOpt.get();
                factorContext.setCurrentProcessingFactor(nextFactorToProcess);
                factorContext.setCurrentStepId(nextStep.getStepId()); // 다음 stepId 설정
                if (currentFlowConfig.getRegisteredFactorOptions() != null) {
                    factorContext.setCurrentFactorOptions(currentFlowConfig.getRegisteredFactorOptions().get(nextFactorToProcess));
                }
                factorContext.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
                contextPersistence.saveContext(factorContext, request);

                responseBody.put("status", "MFA_CONTINUE");
                responseBody.put("message", currentFactorJustCompleted.name() + " 인증 성공. 다음 " + nextFactorToProcess.name() + " 인증을 진행하세요.");
                responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
                responseBody.put("nextFactorType", nextFactorToProcess.name().toUpperCase());
                responseBody.put("nextStepUrl", request.getContextPath() + "/mfa/challenge/" + nextFactorToProcess.name().toLowerCase());
                responseBody.put("nextStepId", nextStep.getStepId());
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            } else {
                log.error("Could not find next AuthenticationStepConfig for factor {} after stepId {} in flow {}.",
                        nextFactorToProcess, currentCompletedStepId, factorContext.getFlowTypeName());
                handleConfigError(response, request, factorContext.getFlowTypeName(), "다음 MFA 단계 설정을 찾을 수 없습니다.");
            }
        } else {
            // 모든 MFA 단계 완료
            log.info("All MFA factors completed for user {}. Proceeding to final token issuance. Session: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.ALL_FACTORS_COMPLETED);
            factorContext.setCurrentStepId(null); // 최종 완료 시 초기화
            factorContext.setCurrentProcessingFactor(null);
            factorContext.setCurrentFactorOptions(null);
            contextPersistence.saveContext(factorContext, request); // 상태 변경 저장

            // 최종 토큰 발급은 UnifiedAuthenticationSuccessHandler 에게 위임
            // (이때 FactorContext는 로드되어 사용되고, 성공 후 삭제될 것임)
            try {
                finalTokenIssuingHandler.processAuthenticationSuccess(request, response, factorContext.getPrimaryAuthentication(), null);
            } catch (Exception e) {
                log.error("ServletException during final token issuance delegation for user {}: {}", factorContext.getUsername(), e.getMessage(), e);
                handleGenericError(response, request, "최종 인증 처리 중 오류가 발생했습니다.");
            }
        }
    }

    private int getStepOrder(AuthenticationFlowConfig flowConfig, String stepId) {
        if (flowConfig == null || !StringUtils.hasText(stepId) || flowConfig.getStepConfigs() == null) return -1;
        return flowConfig.getStepConfigs().stream()
                .filter(s -> stepId.equals(s.getStepId()))
                .mapToInt(AuthenticationStepConfig::getOrder)
                .findFirst()
                .orElse(-1);
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
        // PrimaryAuthenticationSuccessHandler의 것과 동일한 로직 사용 가능
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
            log.warn("Error retrieving PlatformConfig for flow '{}': {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    private Optional<AuthenticationStepConfig> findStepConfigByFactorTypeAndMinOrder(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        // PrimaryAuthenticationSuccessHandler의 것과 동일한 로직 사용 가능
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    private void handleContextError(HttpServletResponse response, HttpServletRequest request, Authentication authentication, String logMessage) throws IOException {
        log.warn("MfaFactorProcessingSuccessHandler: {}. User: {}, Session may have expired or been corrupted.",
                logMessage, (authentication != null ? authentication.getName() : "UnknownUser"));
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "MFA_SESSION_INVALID_CONTEXT", "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI());
        FactorContext existingCtx = contextPersistence.contextLoad(request);
        if (existingCtx != null) contextPersistence.deleteContext(request);
    }
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request, String flowTypeName, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", flowTypeName, message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "FLOW_CONFIG_ERROR", message, request.getRequestURI());
        FactorContext existingCtx = contextPersistence.contextLoad(request);
        if (existingCtx != null) contextPersistence.deleteContext(request);
    }
    private void handleGenericError(HttpServletResponse response, HttpServletRequest request, String message) throws IOException {
        log.error("Generic error during MFA factor processing: {}", message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_PROCESSING_ERROR", message, request.getRequestURI());
        FactorContext existingCtx = contextPersistence.contextLoad(request);
        if (existingCtx != null) contextPersistence.deleteContext(request);
    }
}
