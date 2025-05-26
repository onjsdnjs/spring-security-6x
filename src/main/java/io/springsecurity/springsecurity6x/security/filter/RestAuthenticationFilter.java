package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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
import java.util.UUID;

@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private RequestMatcher requestMatcher = new ParameterRequestMatcher("/api/auth/login", "POST");
    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
            new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final AuthenticationManager authenticationManager;
    private final ContextPersistence contextPersistence;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    // 보안 강화를 위한 추가 필드
    private final BytesKeyGenerator sessionIdGenerator;
    private final SecureRandom secureRandom;
    private final long authDelay = 100; // 타이밍 공격 방지를 위한 최소 지연

    public RestAuthenticationFilter(AuthenticationManager authenticationManager,
                                    ContextPersistence contextPersistence,
                                    ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.contextPersistence = contextPersistence;

        // State Machine 통합자 초기화
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        // 보안 강화: 암호학적으로 안전한 랜덤 생성기
        this.sessionIdGenerator = KeyGenerators.secureRandom(32);
        this.secureRandom = new SecureRandom();
    }

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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 타이밍 공격 방지를 위한 시작 시간 기록
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
     * 타이밍 공격 방지를 위한 최소 지연 보장
     */
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

            // 입력 검증
            validateLoginRequest(login);

            UsernamePasswordAuthenticationToken authRequest =
                    new UsernamePasswordAuthenticationToken(login.username(), login.password());
            return authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            throw new RuntimeException("Authentication request body read failed", e);
        }
    }

    /**
     * 로그인 요청 검증
     */
    private void validateLoginRequest(LoginRequest login) {
        if (!StringUtils.hasText(login.username()) || !StringUtils.hasText(login.password())) {
            throw new IllegalArgumentException("Username and password must not be empty");
        }

        // 사용자명 길이 제한
        if (login.username().length() > 100) {
            throw new IllegalArgumentException("Username too long");
        }

        // 비밀번호 길이 제한
        if (login.password().length() > 200) {
            throw new IllegalArgumentException("Password too long");
        }
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // 기존 FactorContext가 있다면 State Machine에서 정리
        String sessionId = request.getSession().getId();
        FactorContext existingContext = stateMachineIntegrator.getFactorContext(sessionId);
        if (existingContext != null) {
            log.debug("Clearing existing FactorContext (ID: {}) on new primary authentication for user: {}",
                    existingContext.getMfaSessionId(), authentication.getName());

            // State Machine 해제
            if (existingContext.getMfaSessionId() != null) {
                stateMachineIntegrator.releaseStateMachine(existingContext.getMfaSessionId());
            }

            // ContextPersistence 제거 - State Machine이 유일한 저장소
            // contextPersistence.deleteContext(request);
        }

        // 보안 강화: 암호학적으로 안전한 세션 ID 생성
        String mfaSessionId = generateSecureSessionId();
        String flowTypeNameForContext = AuthType.MFA.name().toLowerCase();

        // FactorContext 생성 (초기 상태: PRIMARY_AUTHENTICATION_COMPLETED)
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                MfaState.PRIMARY_AUTHENTICATION_COMPLETED,
                flowTypeNameForContext
        );

        String deviceId = getOrCreateDeviceId(request);
        factorContext.setAttribute("deviceId", deviceId);

        // 보안 정보 추가
        factorContext.setAttribute("clientIp", getClientIpAddress(request));
        factorContext.setAttribute("userAgent", request.getHeader("User-Agent"));
        factorContext.setAttribute("loginTimestamp", System.currentTimeMillis());

        // ContextPersistence 사용하지 않음 - State Machine 초기화 시 저장됨
        // contextPersistence.saveContext(factorContext, request);

        // State Machine 초기화 (여기서 FactorContext가 저장됨)
        stateMachineIntegrator.initializeStateMachine(factorContext, request);

        // PRIMARY_AUTH_SUCCESS 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.PRIMARY_AUTH_SUCCESS, factorContext, request);

        if (!accepted) {
            log.error("State Machine rejected PRIMARY_AUTH_SUCCESS event for session: {}", mfaSessionId);
            // 에러 처리
            unsuccessfulAuthentication(request, response,
                    new AuthenticationException("State Machine initialization failed") {});
            return;
        }

        log.info("FactorContext (ID: {}) created with State Machine integration for user: {}. State: {}",
                factorContext.getMfaSessionId(), factorContext.getUsername(), factorContext.getCurrentState());

        // 첫 번째 단계를 완료된 것으로 마킹 (1차 인증)
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
        if (mfaFlowConfig != null && !mfaFlowConfig.getStepConfigs().isEmpty()) {
            AuthenticationStepConfig primaryAuthStep = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> "PRIMARY".equalsIgnoreCase(step.getType()))
                    .findFirst()
                    .orElse(mfaFlowConfig.getStepConfigs().getFirst());

            factorContext.addCompletedFactor(primaryAuthStep);

            // State Machine 이벤트로 전송하여 업데이트
            stateMachineIntegrator.sendEvent(MfaEvent.PRIMARY_FACTOR_COMPLETED, factorContext, request);
        }

        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * 암호학적으로 안전한 세션 ID 생성
     */
    private String generateSecureSessionId() {
        byte[] bytes = sessionIdGenerator.generateKey();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * 클라이언트 IP 주소 추출 (프록시 고려)
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                // 첫 번째 IP만 사용 (여러 개인 경우)
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();

        // State Machine 정리
        FactorContext context = contextPersistence.contextLoad(request);
        if (context != null && context.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(context.getMfaSessionId());
        }

        contextPersistence.deleteContext(request);

        // 보안 로깅
        log.warn("Authentication failed for user: {} from IP: {}",
                failed.getAuthenticationRequest() != null ?
                        failed.getAuthenticationRequest().getName() : "unknown",
                getClientIpAddress(request));

        failureHandler.onAuthenticationFailure(request, response, failed);
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

    private String getOrCreateDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId)) {
            // 디바이스 ID 검증
            if (!isValidDeviceId(deviceId)) {
                log.warn("Invalid device ID received: {}", deviceId);
                deviceId = null;
            }
        }

        if (!StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(true);
            deviceId = (String) session.getAttribute("transientDeviceId");
            if (!StringUtils.hasText(deviceId)) {
                // 보안 강화: 암호학적으로 안전한 디바이스 ID 생성
                deviceId = generateSecureDeviceId();
                session.setAttribute("transientDeviceId", deviceId);
                log.debug("Generated and stored new transient deviceId in session: {}", deviceId);
            }
        }
        return deviceId;
    }

    /**
     * 디바이스 ID 유효성 검증
     */
    private boolean isValidDeviceId(String deviceId) {
        // UUID 형식 또는 Base64 인코딩된 값 허용
        return deviceId.matches("^[a-zA-Z0-9_-]{22,}$") ||
                deviceId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }

    /**
     * 암호학적으로 안전한 디바이스 ID 생성
     */
    private String generateSecureDeviceId() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}