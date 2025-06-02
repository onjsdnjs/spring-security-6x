package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
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
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 분산환경 완전 대응 RestAuthenticationFilter - 최종 완성판
 *
 * 핵심 개선사항:
 * - Repository별 최적화된 세션 ID 생성 전략
 * - 분산환경에서 세션 ID 유니크성 보장
 * - 자동 충돌 해결 메커니즘
 * - 보안 강화된 세션 관리
 * - 실시간 헬스체킹 및 Fallback
 */
@Slf4j
public class MfaRestAuthenticationFilter extends BaseAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthContextProperties properties;

    // 보안 강화 필드들
    private final BytesKeyGenerator sessionIdGenerator;
    private final SecureRandom secureRandom;
    private final long authDelay;

    // 분산환경 대응 상수들
    private static final int MAX_SESSION_ID_GENERATION_ATTEMPTS = 5;
    private static final int MAX_COLLISION_RESOLUTION_ATTEMPTS = 3;

    private final ObjectMapper mapper;

    public MfaRestAuthenticationFilter(AuthenticationManager authenticationManager,
                                       ApplicationContext applicationContext,
                                       AuthContextProperties properties,
                                       RequestMatcher requestMatcher) {
        super(requestMatcher, authenticationManager, properties);
        this.applicationContext = applicationContext;
        this.properties = properties;

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "mfaSettings cannot be null");

        this.authenticationManager = authenticationManager;
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);
        this.mapper = applicationContext.getBean(ObjectMapper.class);

        // 보안 강화 초기화
        this.sessionIdGenerator = KeyGenerators.secureRandom(32);
        this.secureRandom = new SecureRandom();
        this.authDelay = properties.getMfa().getMinimumDelayMs();

        log.info("RestAuthenticationFilter initialized with {} repository. Distributed sync: {}",
                sessionRepository.getRepositoryType(), sessionRepository.supportsDistributedSync());
    }

    /**
     * 인증 성공 처리 - 분산환경 완전 대응
     */
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {
        // Security Context 설정
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // 기존 세션 정리
        cleanupExistingSession(request, response);

        // 분산환경 대응 세션 ID 생성
        String mfaSessionId = generateSecureDistributedSessionId(request);
        String flowTypeNameForContext = AuthType.MFA.name().toLowerCase();

        // FactorContext 생성
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                MfaState.NONE,
                flowTypeNameForContext
        );

        // 보안 정보 추가
        enhanceFactorContextWithSecurityInfo(factorContext, request);

        try {
            // State Machine 초기화 및 세션 저장
            stateMachineIntegrator.initializeStateMachine(factorContext, request, response);
//            stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

            log.info("State Machine initialized. FactorContext state: {} for user: {} (session: {})",
                    factorContext.getCurrentState(),
                    factorContext.getUsername(),
                    factorContext.getMfaSessionId());

            // 1차 인증 완료 처리
/*            processPrimaryAuthenticationCompletion(factorContext, request);*/

            MfaState actualState = stateMachineIntegrator.getCurrentState(factorContext.getMfaSessionId());
            if (actualState != factorContext.getCurrentState()) {
                log.warn("State mismatch! FactorContext: {}, StateMachine: {} for session: {}",
                        factorContext.getCurrentState(), actualState, factorContext.getMfaSessionId());
            }

            successHandler.onAuthenticationSuccess(request, response, authentication);

        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", mfaSessionId, e);

            // 실패한 세션 정리
            cleanupFailedSession(mfaSessionId, request, response);

            unsuccessfulAuthentication(request, response,
                    new AuthenticationException("State Machine initialization failed", e) {});
        }
    }

    /**
     * 분산환경 대응 안전한 세션 ID 생성
     */
    private String generateSecureDistributedSessionId(HttpServletRequest request) {
        if (sessionRepository.supportsDistributedSync()) {
            return generateDistributedUniqueSessionId(request);
        } else {
            return generateSecureSessionId();
        }
    }

    /**
     * 분산 클러스터용 고유 세션 ID 생성
     */
    private String generateDistributedUniqueSessionId(HttpServletRequest request) {
        log.debug("Generating distributed unique session ID using repository: {}", sessionRepository.getRepositoryType());

        for (int attempt = 0; attempt < MAX_SESSION_ID_GENERATION_ATTEMPTS; attempt++) {
            try {
                String baseId = generateSecureSessionId();
                return sessionRepository.generateUniqueSessionId(baseId, request);

            } catch (MfaSessionRepository.SessionIdGenerationException e) {
                log.warn("Session ID generation failed (attempt: {}): {}", attempt + 1, e.getMessage());

                if (attempt == MAX_SESSION_ID_GENERATION_ATTEMPTS - 1) {
                    return resolveSessionIdGenerationFailure(request);
                }

                // 지수 백오프
                try {
                    Thread.sleep(50L * (1L << Math.min(attempt, 4)));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Session ID generation interrupted", ie);
                }
            }
        }

        // 최종 폴백
        log.warn("All distributed session ID generation attempts failed, using fallback method");
        return generateSecureSessionId();
    }

    /**
     * 세션 ID 생성 실패 시 충돌 해결
     */
    private String resolveSessionIdGenerationFailure(HttpServletRequest request) {
        log.info("Attempting to resolve session ID generation failure using collision resolution");

        try {
            String originalId = generateSecureSessionId();
            return sessionRepository.resolveSessionIdCollision(originalId, request, MAX_COLLISION_RESOLUTION_ATTEMPTS);
        } catch (Exception e) {
            log.error("Failed to resolve session ID collision", e);
            return generateSecureSessionId();
        }
    }

    /**
     * FactorContext 보안 정보 추가
     */
    private void enhanceFactorContextWithSecurityInfo(FactorContext factorContext, HttpServletRequest request) {
        String deviceId = getOrCreateDeviceId(request);
        factorContext.setAttribute("deviceId", deviceId);
        factorContext.setAttribute("clientIp", getClientIpAddress(request));
        factorContext.setAttribute("userAgent", request.getHeader("User-Agent"));
        factorContext.setAttribute("loginTimestamp", System.currentTimeMillis());

        // 분산환경 추가 정보
        factorContext.setAttribute("repositoryType", sessionRepository.getRepositoryType());
        factorContext.setAttribute("distributedSync", sessionRepository.supportsDistributedSync());

        log.debug("Enhanced FactorContext with security info: deviceId={}, repository={}",
                deviceId, sessionRepository.getRepositoryType());
    }

    /**
     * 1차 인증 완료 처리
     */
    private void processPrimaryAuthenticationCompletion(FactorContext factorContext, HttpServletRequest request) {
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
        if (mfaFlowConfig != null && !mfaFlowConfig.getStepConfigs().isEmpty()) {
            AuthenticationStepConfig primaryAuthStep = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> "PRIMARY".equalsIgnoreCase(step.getType()))
                    .findFirst()
                    .orElse(mfaFlowConfig.getStepConfigs().getFirst());

            factorContext.addCompletedFactor(primaryAuthStep);

            stateMachineIntegrator.saveFactorContext(factorContext);
            stateMachineIntegrator.sendEvent(MfaEvent.PRIMARY_AUTH_SUCCESS, factorContext, request);

            log.debug("Primary authentication completed for session: {}", factorContext.getMfaSessionId());
        }
    }

    /**
     * 실패한 세션 정리
     */
    private void cleanupFailedSession(String mfaSessionId, HttpServletRequest request, HttpServletResponse response) {
        try {
            if (sessionRepository.existsSession(mfaSessionId)) {
                sessionRepository.removeSession(mfaSessionId, request, response);
                log.debug("Cleaned up failed session: {}", mfaSessionId);
            }
        } catch (Exception e) {
            log.warn("Failed to cleanup failed session: {}", mfaSessionId, e);
        }
    }

    /**
     * 인증 실패 처리
     */
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        stateMachineIntegrator.cleanupSession(request, response);

        log.warn("Authentication failed for user: {} from IP: {} using repository: {}",
                failed.getAuthenticationRequest() != null ?
                        failed.getAuthenticationRequest().getName() : "unknown",
                getClientIpAddress(request),
                sessionRepository.getRepositoryType());

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    /**
     * 기존 세션 정리
     */
    private void cleanupExistingSession(HttpServletRequest request, HttpServletResponse response) {
        try {
            stateMachineIntegrator.cleanupSession(request, response);
            log.debug("Existing session cleaned up using repository pattern: {}", sessionRepository.getRepositoryType());
        } catch (Exception e) {
            log.warn("Failed to cleanup existing session using {}: {}", sessionRepository.getRepositoryType(), e.getMessage());
        }
    }

    // === 기존 유틸리티 메서드들 ===

    public void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < authDelay) {
            try {
                Thread.sleep(authDelay - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void validateLoginRequest(LoginRequest login) {
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

    public String getClientIpAddress(HttpServletRequest request) {
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
     * 분산환경 대응 디바이스 ID 생성
     */
    private String getOrCreateDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId) && isValidDeviceId(deviceId)) {
            return deviceId;
        }

        if (sessionRepository.supportsDistributedSync()) {
            deviceId = generateDistributedDeviceId(request);
        } else {
            deviceId = generateSecureDeviceId();
        }

        log.debug("Generated deviceId: {} using repository: {}", deviceId, sessionRepository.getRepositoryType());
        return deviceId;
    }

    /**
     * 분산환경용 디바이스 ID 생성
     */
    private String generateDistributedDeviceId(HttpServletRequest request) {
        String clientInfo = getClientIpAddress(request) + "|" +
                (request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "") + "|" +
                System.currentTimeMillis();

        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(clientInfo.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            log.warn("Failed to generate distributed device ID, using fallback", e);
            return generateSecureDeviceId();
        }
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
}
