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
    private final ApplicationContext applicationContext; // PlatformConfig 접근용

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
        log.info("PrimaryAuthenticationSuccessHandler: Primary authentication successful for user: {}. Evaluating FactorContext for MFA.", username);

        // 이전 FactorContext 정리 (RestAuthenticationFilter에서도 할 수 있지만, 핸들러에서 확실히 처리)
        contextPersistence.deleteContext(request);

        // 현재 요청에 해당하는 AuthenticationFlowConfig를 가져와야 함 (MFA 플로우인지, 단일 인증 플로우인지 등)
        // 실제 운영 환경에서는 현재 요청 URI와 매칭되는 SecurityFilterChain의 설정을 통해 flowTypeName을 결정해야 함.
        // 여기서는 임시로 "mfa" 플로우로 가정하거나, RestAuthenticationFilter에서 flowTypeName을 request attribute로 전달받을 수 있음.
        String flowTypeName = determineCurrentFlowTypeName(request); // 이 메소드 구현 필요

        FactorContext mfaCtx = new FactorContext(authentication, flowTypeName);
        String deviceId = getEffectiveDeviceId(request, mfaCtx);
        mfaCtx.setAttribute("deviceId", deviceId);

        // MfaPolicyProvider 호출하여 FactorContext 초기화 (MFA 필요 여부, 다음 상태, 다음 Factor 등 설정)
        // MfaPolicyProvider는 flowTypeName에 해당하는 AuthenticationFlowConfig가 필요할 수 있음
        AuthenticationFlowConfig currentFlowConfig = findFlowConfigByName(flowTypeName);
        if (currentFlowConfig == null && "mfa".equalsIgnoreCase(flowTypeName)) {
            log.error("PrimaryAuthenticationSuccessHandler: MFA flow '{}' configuration not found. Cannot proceed with MFA policy evaluation.", flowTypeName);
            // 적절한 오류 처리 또는 MFA 없이 진행 (정책에 따라)
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONFIG_ERROR", "MFA 설정을 찾을 수 없습니다.", request.getRequestURI());
            return;
        }

        // MfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep는 FactorContext의 상태,
        // mfaRequiredAsPerPolicy, currentProcessingFactor 등을 설정함.
        // 이 단계에서 currentFactorOptions와 currentStepId도 설정해야 함.
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx); // DefaultMfaPolicyProvider는 이 과정에서 currentFactorOptions를 설정하지 않음

        // MfaPolicyProvider 호출 후, currentProcessingFactor가 설정되었다면 해당 Factor의 옵션과 stepId 설정
        if (mfaCtx.getCurrentProcessingFactor() != null && currentFlowConfig != null) {
            AuthType initialFactorType = mfaCtx.getCurrentProcessingFactor();
            // registeredFactorOptions에서 옵션 가져오기
            if (currentFlowConfig.getRegisteredFactorOptions() != null) {
                AuthenticationProcessingOptions factorOptions = currentFlowConfig.getRegisteredFactorOptions().get(initialFactorType);
                mfaCtx.setCurrentFactorOptions(factorOptions);
            }
            // stepConfigs에서 stepId 가져오기
            Optional<AuthenticationStepConfig> initialStepOpt = currentFlowConfig.getStepConfigs().stream()
                    .filter(step -> step.getOrder() > 0 && // 1차 인증(order 0) 제외
                            initialFactorType.name().equalsIgnoreCase(step.getType()))
                    .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder)); // 여러 개 있을 경우 order가 가장 낮은 것
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

        // FactorContext의 최종 평가된 상태를 기반으로 응답 결정
        if (mfaCtx.isMfaRequiredAsPerPolicy()) {
            log.info("PrimaryAuthenticationSuccessHandler: MFA is required for user: {}. Guiding to MFA initiation. Session ID: {}",
                    username, mfaCtx.getMfaSessionId());

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "Primary authentication successful. MFA is required.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("username", username); // 클라이언트 JS에서 사용

            String nextStepUrl;
            if (mfaCtx.getCurrentProcessingFactor() != null &&
                    (mfaCtx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                            mfaCtx.getCurrentState() == MfaState.FACTOR_CHALLENGE_INITIATED)) { // 기존 MfaState 값 사용
                nextStepUrl = request.getContextPath() + "/mfa/challenge/" + mfaCtx.getCurrentProcessingFactor().name().toLowerCase();
            } else { // AWAITING_FACTOR_SELECTION 등
                nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl(); // 예: /mfa/select-factor
            }
            mfaRequiredDetails.put("nextStepUrl", nextStepUrl);

            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);
        } else {
            log.info("PrimaryAuthenticationSuccessHandler: MFA is not required for user: {}. Issuing final tokens.", username);
            String currentDeviceId = (String) mfaCtx.getAttribute("deviceId");

            String accessToken = tokenService.createAccessToken(authentication, currentDeviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, currentDeviceId);
            }

            contextPersistence.deleteContext(request); // MFA 플로우 안 탔으므로 컨텍스트 정리

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

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

    // 실제 구현에서는 현재 HTTP 요청에 매칭된 SecurityFilterChain의 이름을 가져와야 함.
    // Spring Security의 FilterChainProxy 내부 로직을 참조하거나,
    // HttpSecurity 빌드 시점에 해당 정보를 request attribute 등으로 저장해두고 읽어오는 방법 등을 고려.
    // 여기서는 단순 예시로, 요청 경로가 /api/auth/login 이면 "mfa" 플로우로 간주.
    private String determineCurrentFlowTypeName(HttpServletRequest request) {
        // TODO: 요청 URI 또는 다른 식별자를 기반으로 현재 활성화된 AuthenticationFlowConfig의 typeName을 결정하는 로직 구현.
        //       예를 들어, /api/auth/login이면 "mfa", /login이면 "single-form" 등.
        //       또는 SecurityFilterChain 빌드 시 HttpSecurity 공유 객체에 flowTypeName 저장 후 조회.
        if (request.getRequestURI().startsWith("/api/auth/login")) { // 이 URL은 RestAuthenticationFilter가 처리하므로
            return "mfa"; // RestAuthenticationFilter가 MFA 플로우의 1차 인증을 담당한다고 가정
        }
        // 다른 단일 인증 플로우에 대한 처리 경로에 따라 다른 flowTypeName 반환
        // 예: if (request.getRequestURI().startsWith("/login")) return "form"; (만약 form 이라는 이름의 단일 인증 플로우가 있다면)
        log.warn("Could not determine flowTypeName from request URI: {}. Defaulting to 'mfa'. This might be incorrect.", request.getRequestURI());
        return "mfa"; // 기본값 또는 가장 일반적인 MFA 플로우 이름
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
            log.warn("PrimaryAuthenticationSuccessHandler: Could not retrieve PlatformConfig or find flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    private String getEffectiveDeviceId(HttpServletRequest request, @Nullable FactorContext factorContext) {
        String deviceId = null;
        if (factorContext != null) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            if (StringUtils.hasText(deviceId)) {
                log.debug("Using deviceId from existing FactorContext: {}", deviceId);
                return deviceId;
            }
        }
        deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId)) {
            log.debug("Using deviceId from request header 'X-Device-Id': {}", deviceId);
            if (factorContext != null) factorContext.setAttribute("deviceId", deviceId);
            return deviceId;
        }
        HttpSession session = request.getSession(false); // 세션이 없으면 null 반환
        if (session != null) {
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (StringUtils.hasText(deviceId)) {
                log.debug("Using deviceId from HTTP session attribute: {}", deviceId);
                if (factorContext != null) factorContext.setAttribute("deviceId", deviceId);
                return deviceId;
            }
        }
        // 모든 곳에 없으면 새로 생성 (UUID)하고 FactorContext에만 저장 (세션에는 저장하지 않음)
        deviceId = UUID.randomUUID().toString();
        log.debug("No existing deviceId found, generated new transient deviceId: {}", deviceId);
        if (factorContext != null) {
            factorContext.setAttribute("deviceId", deviceId);
        }
        return deviceId;
    }
}