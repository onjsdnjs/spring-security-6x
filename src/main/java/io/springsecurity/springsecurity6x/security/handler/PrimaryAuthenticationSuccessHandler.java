package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;

@Slf4j
@Component
public class PrimaryAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;

    public PrimaryAuthenticationSuccessHandler(ContextPersistence contextPersistence,
                                               MfaPolicyProvider mfaPolicyProvider,
                                               TokenService tokenService,
                                               AuthContextProperties authContextProperties,
                                               AuthResponseWriter responseWriter,
                                               ApplicationContext applicationContext) {
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.tokenService = tokenService;
        this.authContextProperties = authContextProperties;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        String username = authentication.getName();
        log.info("PrimaryAuthenticationSuccessHandler: 1FA success for user: {}. Evaluating MFA.", username);

        contextPersistence.deleteContext(request); // 이전 MFA 세션 정리

        String flowTypeName = determineCurrentFlowTypeName(request); // 현재 요청에 대한 Flow Type Name 결정
        FactorContext mfaCtx = new FactorContext(authentication, flowTypeName); // flowTypeName 전달
        String deviceId = getEffectiveDeviceId(request, mfaCtx);
        mfaCtx.setAttribute("deviceId", deviceId);

        AuthenticationFlowConfig currentFlowConfig = findFlowConfigByName(flowTypeName);
        if (currentFlowConfig == null && "mfa".equalsIgnoreCase(flowTypeName)) { // MFA 플로우인데 설정을 못 찾으면 오류
            log.error("PrimaryAuthenticationSuccessHandler: MFA flow '{}' config not found for user {}.", flowTypeName, username);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONFIG_ERROR", "MFA 설정을 찾을 수 없습니다.", request.getRequestURI());
            return;
        }

        // MfaPolicyProvider가 FactorContext의 상태, mfaRequiredAsPerPolicy, currentProcessingFactor 등을 설정
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);

        // MfaPolicyProvider 호출 후, currentProcessingFactor가 설정되었다면 해당 Factor의 옵션과 stepId 설정
        if (mfaCtx.getCurrentProcessingFactor() != null && currentFlowConfig != null) {
            AuthType initialFactorType = mfaCtx.getCurrentProcessingFactor();
            if (currentFlowConfig.getRegisteredFactorOptions() != null) {
                AuthenticationProcessingOptions factorOptions = currentFlowConfig.getRegisteredFactorOptions().get(initialFactorType);
                mfaCtx.setCurrentFactorOptions(factorOptions);
            }
            // AuthenticationStepConfig에서 stepId 가져오기
            Optional<AuthenticationStepConfig> initialStepOpt = findStepConfig(currentFlowConfig, initialFactorType, 0); // 1차 인증 다음이므로 order > 0 인 Factor 검색
            if (initialStepOpt.isPresent()) {
                mfaCtx.setCurrentStepId(initialStepOpt.get().getStepId());
            } else {
                log.warn("PrimaryAuthenticationSuccessHandler: Could not find AuthenticationStepConfig for initial factor {} in flow {}. currentStepId will be null.",
                        initialFactorType, flowTypeName);
            }
        }

        contextPersistence.saveContext(mfaCtx, request);
        log.debug("PrimaryAuthenticationSuccessHandler: FactorContext (ID: {}, Flow: {}) saved for user {} with state: {}, factor: {}, stepId: {}",
                mfaCtx.getMfaSessionId(), mfaCtx.getFlowTypeName(), username, mfaCtx.getCurrentState(), mfaCtx.getCurrentProcessingFactor(), mfaCtx.getCurrentStepId());

        if (mfaCtx.isMfaRequiredAsPerPolicy()) {
            log.info("PrimaryAuthenticationSuccessHandler: MFA required for user: {}. Session ID: {}. Guiding to MFA.",
                    username, mfaCtx.getMfaSessionId());

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("username", username);

            String nextStepUrl;
            // MfaPolicyProvider가 currentProcessingFactor를 설정하고, 상태를 AWAITING_FACTOR_CHALLENGE_INITIATION으로 변경한 경우
            if (mfaCtx.getCurrentProcessingFactor() != null &&
                    mfaCtx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {
                // 해당 Factor의 챌린지 UI 페이지로 직접 안내
                nextStepUrl = request.getContextPath() + "/mfa/challenge/" + mfaCtx.getCurrentProcessingFactor().name().toLowerCase();
                log.debug("Next step for MFA: Directly to challenge UI for factor {} -> {}", mfaCtx.getCurrentProcessingFactor(), nextStepUrl);
            } else {
                // 기본적으로는 Factor 선택 페이지로 유도 (MfaState.AWAITING_FACTOR_SELECTION 상태일 것임)
                // 또는 AuthContextProperties의 mfa.initiateUrl 사용 (이것이 /mfa/select-factor 와 같은 UI 페이지여야 함)
                nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl();
                log.debug("Next step for MFA: To factor selection or initiate URL -> {}", nextStepUrl);
            }
            mfaRequiredDetails.put("nextStepUrl", nextStepUrl);

            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);
        } else {
            // MFA 불필요: 최종 인증 성공 처리 (토큰 발급)
            log.info("PrimaryAuthenticationSuccessHandler: MFA not required for user: {}. Issuing final tokens.", username);
            // ... (토큰 발급 로직은 이전 답변과 동일하게 유지) ...
            String currentDeviceId = (String) mfaCtx.getAttribute("deviceId");
            String accessToken = tokenService.createAccessToken(authentication, currentDeviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, currentDeviceId);
            }
            contextPersistence.deleteContext(request); // 컨텍스트 정리
            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);
            // ... (응답 작성 로직) ...
            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            Map<String, Object> responseBody = new HashMap<>(transportResult.getBody());
            responseBody.put("status", "SUCCESS");
            responseBody.put("message", "Authentication successful.");
            responseBody.put("redirectUrl", "/"); // 예시
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        }
    }

    // 현재 요청에 대한 Flow Type Name 결정 (실제 구현 필요)
    private String determineCurrentFlowTypeName(HttpServletRequest request) {
        // RestAuthenticationFilter의 loginProcessingUrl (예: /api/auth/login)은
        // PlatformSecurityConfig에서 MFA 플로우에 속하도록 DSL로 정의되어야 함.
        // 해당 SecurityFilterChain에 매핑된 AuthenticationFlowConfig의 typeName을 가져와야 함.
        // 여기서는 간단히 "/api/auth/login" 요청은 "mfa" 플로우라고 가정.
        if (request.getRequestURI().equals("/api/auth/login")) { // RestAuthenticationFilter의 requestMatcher와 일치해야 함
            return "mfa";
        }
        // 다른 단일 인증 요청 경로에 따라 다른 flowTypeName 반환 가능
        // 예: if (request.getRequestURI().equals("/login")) return "form";
        log.warn("Cannot determine flowTypeName for URI: {}. Defaulting to 'unknown_flow'. This needs proper implementation.", request.getRequestURI());
        return "unknown_flow"; // 실제로는 예외를 던지거나, 더 정확한 로직 필요
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
                        .orElseGet(() -> {
                            log.warn("No AuthenticationFlowConfig found with typeName: {}", flowTypeName);
                            return null;
                        });
            }
        } catch (Exception e) {
            log.warn("PrimaryAuthenticationSuccessHandler: Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    private Optional<AuthenticationStepConfig> findStepConfig(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }


    private String getEffectiveDeviceId(HttpServletRequest request, @Nullable FactorContext factorContext) {
        // ... (이전 답변의 getEffectiveDeviceId 로직과 동일하게 사용)
        String deviceId = null;
        if (factorContext != null) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            if (StringUtils.hasText(deviceId)) return deviceId;
        }
        deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId)) {
            if (factorContext != null) factorContext.setAttribute("deviceId", deviceId);
            return deviceId;
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (StringUtils.hasText(deviceId)) {
                if (factorContext != null) factorContext.setAttribute("deviceId", deviceId);
                return deviceId;
            }
        }
        deviceId = UUID.randomUUID().toString();
        if (factorContext != null) {
            factorContext.setAttribute("deviceId", deviceId);
        } else {
            HttpSession newSession = request.getSession(true);
            newSession.setAttribute("sessionDeviceIdForAuth", deviceId);
        }
        return deviceId;
    }
}