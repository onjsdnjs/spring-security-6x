package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Repository 패턴 기반 완전 일원화된 RestAuthenticationFilter
 * - 기존 클래스 구조와 메서드 시그니처 완전 유지
 * - 설정에 따라 HTTP Session, Redis, Memory 등 자동 선택
 * - MfaStateMachineIntegrator를 통한 완전한 캡슐화
 * - State Machine 기반 일원화 유지
 */
@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final AuthContextProperties properties;

    // 보안 강화를 위한 필드들 (기존 완전 유지)
    private final BytesKeyGenerator sessionIdGenerator;
    private final SecureRandom secureRandom;
    private final long authDelay;

    // 기존 필드들 완전 유지
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private RequestMatcher requestMatcher = new ParameterRequestMatcher("/api/auth/login", "POST");
    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
            new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    public RestAuthenticationFilter(AuthenticationManager authenticationManager,
                                    ApplicationContext applicationContext,
                                    AuthContextProperties properties) {
        this.applicationContext = applicationContext;
        this.properties = properties;

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "mfaSettings cannot be null");

        this.authenticationManager = authenticationManager;

        // State Machine 통합자 초기화 (Repository 패턴 사용) (기존 유지)
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        // 보안 강화: 암호학적으로 안전한 랜덤 생성기 (기존 유지)
        this.sessionIdGenerator = KeyGenerators.secureRandom(32);
        this.secureRandom = new SecureRandom();

        // MfaSettings에서 지연 시간 설정 (기존 유지)
        this.authDelay = properties.getMfa().getMinimumDelayMs();

        log.info("RestAuthenticationFilter initialized with {} and unified State Machine Service",
                stateMachineIntegrator.getSessionRepositoryInfo());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();

        try {
            Authentication authResult = attemptAuthentication(request, response);
            if (authResult == null) {
                ensureMinimumDelay(startTime);
                filterChain.doFilter(request, response);
                return;
            }

            successfulAuthentication(request, response, filterChain, authResult);

        } catch (AuthenticationException ex) {
            ensureMinimumDelay(startTime);
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    /**
     * 완전 일원화: 인증 성공 처리 (기존 메서드 구조 완전 유지)
     * - Repository 패턴을 통한 자동 저장소 선택
     * - State Machine 초기화 및 FactorContext 저장 일원화
     */
    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // Repository 패턴을 통한 기존 세션 정리 (자동으로 적절한 저장소에서)
        cleanupExistingSession(request, response);

        // 보안 강화: 암호학적으로 안전한 세션 ID 생성 (기존 유지)
        String mfaSessionId = generateSecureSessionId();
        String flowTypeNameForContext = AuthType.MFA.name().toLowerCase();

        // FactorContext 생성 (기존 유지)
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                MfaState.PRIMARY_AUTHENTICATION_COMPLETED,
                flowTypeNameForContext
        );

        // 보안 정보 추가 (기존 유지)
        String deviceId = getOrCreateDeviceId(request);
        factorContext.setAttribute("deviceId", deviceId);
        factorContext.setAttribute("clientIp", getClientIpAddress(request));
        factorContext.setAttribute("userAgent", request.getHeader("User-Agent"));
        factorContext.setAttribute("loginTimestamp", System.currentTimeMillis());

        // 완전 일원화: State Machine 초기화 및 Repository를 통한 세션 저장 (기존 유지)
        try {
            // Repository 패턴을 통해 자동으로 적절한 저장소 사용 (HTTP Session, Redis, Memory 등)
            stateMachineIntegrator.initializeStateMachine(factorContext, request, response);

            log.info("Unified State Machine initialized for user: {} with session: {} using repository",
                    factorContext.getUsername(), factorContext.getMfaSessionId());

            // 첫 번째 단계를 완료된 것으로 마킹 (1차 인증) (기존 유지)
            AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
            if (mfaFlowConfig != null && !mfaFlowConfig.getStepConfigs().isEmpty()) {
                AuthenticationStepConfig primaryAuthStep = mfaFlowConfig.getStepConfigs().stream()
                        .filter(step -> "PRIMARY".equalsIgnoreCase(step.getType()))
                        .findFirst()
                        .orElse(mfaFlowConfig.getStepConfigs().get(0));

                factorContext.addCompletedFactor(primaryAuthStep);

                // State Machine에 저장 및 이벤트 전송 (일원화) (기존 유지)
                stateMachineIntegrator.saveFactorContext(factorContext);
                stateMachineIntegrator.sendEvent(MfaEvent.PRIMARY_FACTOR_COMPLETED, factorContext, request);
            }

            successHandler.onAuthenticationSuccess(request, response, authentication);

        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", mfaSessionId, e);
            unsuccessfulAuthentication(request, response,
                    new AuthenticationException("State Machine initialization failed", e) {});
        }
    }

    /**
     * 완전 일원화: 인증 실패 처리 (기존 메서드 구조 완전 유지)
     * - Repository 패턴을 통한 State Machine 정리
     */
    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();

        // Repository 패턴을 통한 State Machine 정리 (자동으로 적절한 저장소에서)
        stateMachineIntegrator.cleanupSession(request, response);

        // 보안 로깅 (기존 유지)
        log.warn("Authentication failed for user: {} from IP: {}",
                failed.getAuthenticationRequest() != null ?
                        failed.getAuthenticationRequest().getName() : "unknown",
                getClientIpAddress(request));

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    // === Repository 패턴 활용 유틸리티 메서드들 ===

    /**
     * Repository 패턴을 통한 기존 세션 정리
     */
    private void cleanupExistingSession(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Repository가 알아서 적절한 저장소에서 기존 세션 정리
            stateMachineIntegrator.cleanupSession(request, response);
            log.debug("Existing session cleaned up using repository pattern");
        } catch (Exception e) {
            log.warn("Failed to cleanup existing session: {}", e.getMessage());
            // 정리 실패는 치명적이지 않으므로 계속 진행
        }
    }

    // === 기존 유틸리티 메서드들 완전 유지 ===

    private void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < authDelay) {
            try {
                Thread.sleep(authDelay - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            LoginRequest login = mapper.readValue(request.getInputStream(), LoginRequest.class);
            validateLoginRequest(login);

            UsernamePasswordAuthenticationToken authRequest =
                    new UsernamePasswordAuthenticationToken(login.username(), login.password());
            return authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            throw new RuntimeException("Authentication request body read failed", e);
        }
    }

    private void validateLoginRequest(LoginRequest login) {
        if (!StringUtils.hasText(login.username()) || !StringUtils.hasText(login.password())) {
            throw new IllegalArgumentException("Username and password must not be empty");
        }

        if (login.username().length() > 100) {
            throw new IllegalArgumentException("Username too long");
        }

        if (login.password().length() > 200) {
            throw new IllegalArgumentException("Password too long");
        }
    }

    private String generateSecureSessionId() {
        byte[] bytes = sessionIdGenerator.generateKey();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {
        if (!AuthType.MFA.name().equalsIgnoreCase(flowTypeName)) {
            log.warn("Attempting to find non-MFA flow config: {}", flowTypeName);
            return null;
        }
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig.getFlows() != null) {
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

    /**
     * 디바이스 ID 생성/조회 (기존 로직 유지, 추후 Repository 패턴 확장 가능)
     */
    private String getOrCreateDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId) && isValidDeviceId(deviceId)) {
            return deviceId;
        }

        // 임시 디바이스 ID 생성 (추후 Repository 패턴으로 확장 가능)
        deviceId = generateSecureDeviceId();
        log.debug("Generated temporary deviceId: {}", deviceId);

        return deviceId;
    }

    private boolean isValidDeviceId(String deviceId) {
        return deviceId.matches("^[a-zA-Z0-9_-]{22,}$") ||
                deviceId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }

    private String generateSecureDeviceId() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // === 기존 Setter 메서드들 완전 유지 ===

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.requestMatcher = requestMatcher;
    }

    public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }
}