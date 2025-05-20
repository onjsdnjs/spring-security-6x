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
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class UnifiedAuthenticationSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final String defaultTargetUrl = "/"; // 필요시 생성자 또는 프로퍼티로 주입

    // 일반 인증 성공 시 (1차 인증, 단일 인증 최종)
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        processAuthenticationSuccess(request, response, authentication, null);
    }

    // OTT 토큰 생성 성공 시 (단일 OTT 로그인 시 이메일 발송 후 MagicLinkHandler가 호출)
    // 또는 MFA 플로우 내 OTT Factor 성공 시 MfaStepFactorSuccessHandler가 processMfaStepSuccess 호출
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !Objects.equals(authentication.getName(), oneTimeToken.getUsername())) {
            log.warn("UnifiedAuthSuccessHandler (OTT): Auth mismatch or not found after OTT. OTT User: {}. Auth User: {}",
                    oneTimeToken.getUsername(), (authentication != null ? authentication.getName() : "N/A"));
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "OTT_AUTH_CONTEXT_ERROR", "OTT 인증 후 사용자 컨텍스트 오류.", request.getRequestURI());
            return;
        }
        processAuthenticationSuccess(request, response, authentication, oneTimeToken);
    }


    /**
     * 모든 인증 성공 시나리오를 처리하는 통합 메소드.
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param authentication 성공한 Authentication 객체
     * @param consumedOtt (선택적) 만약 OTT 인증을 통해 이 핸들러가 호출된 경우, 소비된 OneTimeToken
     * @throws IOException
     */
    public void processAuthenticationSuccess(HttpServletRequest request,
                                             HttpServletResponse response,
                                             Authentication authentication,
                                             @Nullable OneTimeToken consumedOtt) throws IOException {

        String username = authentication.getName();
        log.info("UnifiedAuthenticationSuccessHandler: Processing authentication success for user: {}. URI: {}", username, request.getRequestURI());

        // 1. FactorContext 로드 또는 생성
        FactorContext factorContext = contextPersistence.contextLoad(request);
        String flowTypeName;
        AuthenticationFlowConfig currentFlowConfig = null;

        if (factorContext != null && Objects.equals(factorContext.getUsername(), username)) {
            // 기존 MFA 세션이 있고, 사용자가 일치하는 경우 (예: MfaStepBasedSuccessHandler에서 모든 Factor 완료 후 호출)
            flowTypeName = factorContext.getFlowTypeName();
            log.debug("Reusing existing FactorContext (ID: {}, Flow: {}) for user: {}",
                    factorContext.getMfaSessionId(), flowTypeName, username);
            currentFlowConfig = findFlowConfigByName(flowTypeName);
            if (currentFlowConfig == null && "mfa".equalsIgnoreCase(flowTypeName)) {
                handleConfigError(response, request, flowTypeName, "MFA 플로우 설정을 찾을 수 없습니다 (기존 컨텍스트).");
                return;
            }
            // deviceId는 이미 FactorContext에 있어야 함.
        } else {
            // 새로운 1차 인증 성공 또는 단일 인증 성공의 경우
            if (factorContext != null) {
                log.warn("Existing FactorContext found but username mismatch or invalid. Clearing it. ContextUser: {}, AuthUser: {}",
                        factorContext.getUsername(), username);
                contextPersistence.deleteContext(request);
            }
            flowTypeName = determineCurrentFlowTypeName(request); // 현재 요청 기반으로 flowTypeName 결정
            factorContext = new FactorContext(authentication, flowTypeName);
            String deviceId = getEffectiveDeviceId(request); // deviceId 결정
            factorContext.setAttribute("deviceId", deviceId);

            currentFlowConfig = findFlowConfigByName(flowTypeName);
            if (currentFlowConfig == null && "mfa".equalsIgnoreCase(flowTypeName)) {
                handleConfigError(response, request, flowTypeName, "MFA 플로우 설정을 찾을 수 없습니다 (신규 컨텍스트).");
                return;
            }
            // MfaPolicyProvider를 호출하여 MFA 필요 여부 및 초기 단계 설정
            // 이 호출은 factorContext의 상태, mfaRequiredAsPerPolicy, currentProcessingFactor 등을 설정.
            mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, factorContext);
        }

        // MfaPolicyProvider 호출 후, FactorContext에 currentProcessingFactor가 설정되었고,
        // 이것이 2차 인증 요소라면 해당 Factor의 옵션과 stepId를 설정해야 함.
        if (factorContext.isMfaRequiredAsPerPolicy() && factorContext.getCurrentProcessingFactor() != null && currentFlowConfig != null) {
            AuthType initialFactorType = factorContext.getCurrentProcessingFactor();
            // registeredFactorOptions 에서 옵션 가져오기
            AuthenticationProcessingOptions factorOptions = currentFlowConfig.getRegisteredFactorOptions().get(initialFactorType);
            factorContext.setCurrentFactorOptions(factorOptions);
            // stepConfigs 에서 stepId 가져오기
            // MFA 플로우에서 1차 인증은 order 0, 2차 인증은 order > 0
            Optional<AuthenticationStepConfig> initialStepOpt = findStepConfigByFactorTypeAndMinOrder(currentFlowConfig, initialFactorType, 0);
            if (initialStepOpt.isPresent()) {
                factorContext.setCurrentStepId(initialStepOpt.get().getStepId());
            } else {
                log.warn("UnifiedAuthenticationSuccessHandler: Could not find AuthenticationStepConfig for initial factor {} in flow {}. currentStepId will be null.",
                        initialFactorType, flowTypeName);
            }
        }

        contextPersistence.saveContext(factorContext, request); // 변경된 FactorContext 저장
        log.debug("UnifiedAuthenticationSuccessHandler: FactorContext (ID: {}, Flow: {}) updated. State: {}, Factor: {}, StepId: {}",
                factorContext.getMfaSessionId(), factorContext.getFlowTypeName(), factorContext.getCurrentState(),
                factorContext.getCurrentProcessingFactor(), factorContext.getCurrentStepId());


        // 2. MFA 필요 여부에 따라 분기
        if (factorContext.isMfaRequiredAsPerPolicy() && factorContext.getCurrentState() != MfaState.ALL_FACTORS_COMPLETED) {
            // MFA 필요하고 아직 모든 Factor가 완료되지 않음 -> MFA 시작/계속 안내
            log.info("MFA is required for user: {}. Session ID: {}. Guiding to MFA.",
                    username, factorContext.getMfaSessionId());

            Map<String, Object> mfaResponse = new HashMap<>();
            mfaResponse.put("status", "MFA_REQUIRED");
            mfaResponse.put("message", "1차 인증 성공. 2차 인증을 진행하세요.");
            mfaResponse.put("mfaSessionId", factorContext.getMfaSessionId());
            mfaResponse.put("username", username);

            String nextStepUrl;
            if (factorContext.getCurrentProcessingFactor() != null &&
                    factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {
                nextStepUrl = request.getContextPath() + "/mfa/challenge/" + factorContext.getCurrentProcessingFactor().name().toLowerCase();
                mfaResponse.put("nextFactorType", factorContext.getCurrentProcessingFactor().name().toUpperCase());
                mfaResponse.put("nextStepId", factorContext.getCurrentStepId());
            } else { // AWAITING_FACTOR_SELECTION 등
                nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl();
            }
            mfaResponse.put("nextStepUrl", nextStepUrl);

            responseWriter.writeSuccessResponse(response, mfaResponse, HttpServletResponse.SC_OK);

        } else {
            // MFA 불필요 또는 모든 MFA Factor 완료 -> 최종 토큰 발급
            log.info("MFA not required or all factors completed for user: {}. Issuing final tokens.", username);
            String deviceIdFromCtx = (String) factorContext.getAttribute("deviceId");

            String accessToken = tokenService.createAccessToken(authentication, deviceIdFromCtx);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceIdFromCtx);
            }

            contextPersistence.deleteContext(request); // MFA 컨텍스트 정리 (최종 성공이므로)

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);
            Map<String, Object> responseBody = new HashMap<>(transportResult.getBody());
            responseBody.put("status", "SUCCESS"); // 또는 "MFA_COMPLETE"
            responseBody.put("message", "인증에 성공했습니다.");
            responseBody.put("redirectUrl", determineTargetUrl(request, authentication)); // SavedRequest 처리

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        }
    }


    // Helper methods (이전 답변들과 유사, 필요시 private static 또는 유틸 클래스로 분리)
    private String determineCurrentFlowTypeName(HttpServletRequest request) {
        // TODO: 실제 프로덕션에서는 요청 URI, 헤더, 또는 SecurityFilterChain 매칭 정보를 기반으로
        //       현재 요청이 어떤 AuthenticationFlowConfig에 속하는지 정확히 결정해야 합니다.
        //       PlatformContext나 HttpSecurity 공유 객체를 통해 이 정보를 가져올 수 있어야 합니다.
        String requestUri = request.getRequestURI();
        if (requestUri.startsWith("/api/auth/login")) return "mfa"; // MFA 플로우의 1차 인증 경로 예시
        if (requestUri.startsWith("/login")) return "form";      // 단일 Form 로그인 플로우 예시
        if (requestUri.startsWith("/login/ott")) return "ott_flow"; // 단일 OTT 플로우 예시 (이름은 DSL 정의에 따라)
        // ... 기타 플로우 ...
        log.warn("Could not determine flowTypeName from request URI: {}. Defaulting to 'default_flow'. This requires robust implementation.", request.getRequestURI());
        return "default_flow"; // 또는 예외 발생
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            return platformConfig.getFlows().stream()
                    .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElseGet(() -> {
                        log.warn("No AuthenticationFlowConfig found with typeName: {}", flowTypeName);
                        return null;
                    });
        } catch (Exception e) {
            log.warn("Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    private Optional<AuthenticationStepConfig> findStepConfigByFactorTypeAndMinOrder(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive && // 1차 인증(order 0) 이후의 스텝
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    private String getEffectiveDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId)) {
            return deviceId;
        }
        HttpSession session = request.getSession(false); // 없으면 null
        if (session != null) {
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (StringUtils.hasText(deviceId)) {
                return deviceId;
            }
        }
        // 새로운 deviceId 생성 및 세션에 저장 (선택적)
        deviceId = UUID.randomUUID().toString();
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute("sessionDeviceIdForAuth", deviceId);
        log.debug("Generated and stored new sessionDeviceIdForAuth: {}", deviceId);
        return deviceId;
    }

    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication) {
        // SavedRequestAwareAuthenticationSuccessHandler의 로직 활용 가능
        org.springframework.security.web.savedrequest.SavedRequest savedRequest =
                (org.springframework.security.web.savedrequest.SavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        if (savedRequest != null) {
            request.getSession().removeAttribute("SPRING_SECURITY_SAVED_REQUEST");
            return savedRequest.getRedirectUrl();
        }
        return defaultTargetUrl;
    }
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request, String flowTypeName, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", flowTypeName, message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "FLOW_CONFIG_ERROR", message, request.getRequestURI());
    }
}
