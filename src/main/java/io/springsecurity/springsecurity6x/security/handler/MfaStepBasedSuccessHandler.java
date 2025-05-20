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
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;

@Slf4j
@Component
public class MfaStepBasedSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext; // PlatformConfig 접근용

    public MfaStepBasedSuccessHandler(TokenService tokenService,
                                      MfaPolicyProvider mfaPolicyProvider,
                                      ContextPersistence contextPersistence,
                                      AuthResponseWriter responseWriter,
                                      ApplicationContext applicationContext) {
        this.tokenService = tokenService;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.contextPersistence = contextPersistence;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MfaStepBasedSuccessHandler.onAuthenticationSuccess called for user: {} (Principal type: {})",
                authentication.getName(), authentication.getPrincipal().getClass().getSimpleName());
        processMfaStepSuccess(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !Objects.equals(authentication.getName(), token.getUsername())) {
            log.warn("MfaStepBasedSuccessHandler.handle (OTT): Authentication mismatch or not found in SecurityContext after OTT. OTT User: {}. Auth User: {}",
                    token.getUsername(), (authentication != null ? authentication.getName() : "N/A"));
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "OTT_AUTH_CONTEXT_ERROR", "OTT 인증 후 사용자 컨텍스트 오류.", request.getRequestURI());
            return;
        }
        log.debug("MfaStepBasedSuccessHandler.handle (OTT) called for authenticated user: {} via OTT for: {}",
                authentication.getName(), token.getUsername());
        processMfaStepSuccess(request, response, authentication);
    }

    private void processMfaStepSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            log.warn("MFA Step Success Handler: FactorContext is null or username mismatch. User: {}, Context User: {}. Session may have expired or been corrupted.",
                    authentication.getName(), (factorContext != null ? factorContext.getUsername() : "N/A"));
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "MFA_SESSION_INVALID_OR_MISMATCH", "MFA 세션이 유효하지 않거나 사용자 정보가 일치하지 않습니다.", request.getRequestURI());
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        if (currentFactorJustCompleted == null) {
            log.error("MFA Step Success Handler: Critical error - currentProcessingFactor is null in FactorContext. Session: {}, User: {}", factorContext.getMfaSessionId(), factorContext.getUsername());
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONTEXT_CORRUPTED_FACTOR", "MFA 컨텍스트에 현재 처리 중인 인증 요소 정보가 없습니다.", request.getRequestURI());
            contextPersistence.deleteContext(request);
            return;
        }

        log.info("MFA Step Success: Factor {} for user {} (session {}) completed successfully.",
                currentFactorJustCompleted, factorContext.getUsername(), factorContext.getMfaSessionId());

        factorContext.addCompletedFactor(currentFactorJustCompleted);
        int currentFactorOrder = getCurrentFactorOrder(factorContext); // 현재 완료된 Factor의 order 가져오기

        // MfaPolicyProvider가 다음 Factor를 결정할 때, flowConfig가 필요하다면 주입 또는 조회
        AuthenticationFlowConfig currentFlowConfig = findFlowConfigByName(factorContext.getFlowTypeName());
        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactorToProcess(factorContext); // 이 메소드는 FactorContext만으로 다음 Factor 결정 가능해야 함
        Map<String, Object> responseBody = new HashMap<>();

        if (nextFactorToProcess != null) {
            log.info("MFA Step Success: Next factor to process for user {} is {}. Session: {}",
                    factorContext.getUsername(), nextFactorToProcess, factorContext.getMfaSessionId());

            factorContext.setCurrentProcessingFactor(nextFactorToProcess);
            // 다음 Factor에 대한 AuthenticationStepConfig를 찾아 stepId와 options 설정
            if (currentFlowConfig != null) {
                Optional<AuthenticationStepConfig> nextStepOpt = currentFlowConfig.getStepConfigs().stream()
                        .filter(step -> step.getOrder() > currentFactorOrder && // 현재 완료된 Factor보다 높은 order
                                nextFactorToProcess.name().equalsIgnoreCase(step.getType()))
                        .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

                if (nextStepOpt.isPresent()) {
                    AuthenticationStepConfig nextStep = nextStepOpt.get();
                    factorContext.setCurrentStepId(nextStep.getStepId());
                    if (currentFlowConfig.getRegisteredFactorOptions() != null) {
                        factorContext.setCurrentFactorOptions(currentFlowConfig.getRegisteredFactorOptions().get(nextFactorToProcess));
                    }
                } else {
                    log.error("Could not find next AuthenticationStepConfig for factor {} in flow {}. This is a configuration error.",
                            nextFactorToProcess, factorContext.getFlowTypeName());
                    // 적절한 오류 처리, 예: AWAITING_FACTOR_SELECTION으로 보내거나 에러 응답
                    factorContext.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                    factorContext.setCurrentProcessingFactor(null);
                    factorContext.setCurrentFactorOptions(null);
                    factorContext.setCurrentStepId(null);
                    contextPersistence.saveContext(factorContext, request);
                    responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_FLOW_CONFIG_ERROR", "다음 MFA 단계를 찾을 수 없습니다.", request.getRequestURI());
                    return;
                }
            } else {
                log.error("MFA Flow Configuration not found for flow: {}. Cannot set next stepId and options.", factorContext.getFlowTypeName());
                // FlowConfig를 찾을 수 없는 경우의 처리
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_FLOW_CONFIG_UNAVAILABLE", "MFA 플로우 설정을 찾을 수 없습니다.", request.getRequestURI());
                return;
            }

            factorContext.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
            contextPersistence.saveContext(factorContext, request);

            responseBody.put("status", "MFA_CONTINUE");
            responseBody.put("message", currentFactorJustCompleted.name() + " 인증 성공. 다음 " + nextFactorToProcess.name() + " 인증을 진행하세요.");
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
            responseBody.put("nextFactorType", nextFactorToProcess.name().toUpperCase());
            responseBody.put("nextStepUrl", request.getContextPath() + "/mfa/challenge/" + nextFactorToProcess.name().toLowerCase());
            responseBody.put("nextStepId", factorContext.getCurrentStepId()); // 다음 stepId도 전달 (클라이언트에서 사용 가능)
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        } else {
            // 모든 MFA 단계 완료
            log.info("MFA Step Success: All MFA factors completed for user {}. Issuing final tokens. Session: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.ALL_FACTORS_COMPLETED);
            factorContext.setCurrentStepId(null); // 최종 완료 시 currentStepId 초기화

            String deviceId = (String) factorContext.getAttribute("deviceId");
            Authentication finalAuthentication = factorContext.getPrimaryAuthentication();

            String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceId);
            }

            contextPersistence.deleteContext(request); // MFA 컨텍스트 정리

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            Map<String, Object> finalSuccessBody = new HashMap<>(transportResult.getBody());
            finalSuccessBody.put("status", "MFA_COMPLETE");
            finalSuccessBody.put("message", "모든 MFA 인증이 성공적으로 완료되었습니다.");
            finalSuccessBody.put("redirectUrl", "/");
            responseWriter.writeSuccessResponse(response, finalSuccessBody, HttpServletResponse.SC_OK);
        }
    }

    private int getCurrentFactorOrder(FactorContext factorContext) {
        if (factorContext.getCurrentStepId() == null) return -1; // stepId가 없으면 order도 알 수 없음

        AuthenticationFlowConfig flowConfig = findFlowConfigByName(factorContext.getFlowTypeName());
        if (flowConfig != null && flowConfig.getStepConfigs() != null) {
            return flowConfig.getStepConfigs().stream()
                    .filter(step -> factorContext.getCurrentStepId().equals(step.getStepId()))
                    .mapToInt(AuthenticationStepConfig::getOrder)
                    .findFirst()
                    .orElse(-1); // 해당 stepId를 찾지 못한 경우
        }
        return -1;
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
            log.warn("MfaStepBasedSuccessHandler: Could not retrieve PlatformConfig or find flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }
}