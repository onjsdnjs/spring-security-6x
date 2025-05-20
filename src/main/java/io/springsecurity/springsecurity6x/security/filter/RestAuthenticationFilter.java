package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType; // AuthType 추가
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final RequestMatcher requestMatcher;
    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final AuthenticationManager authenticationManager;
    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ApplicationContext applicationContext;
    // private final String mfaInitiateUrl; // 더 이상 이 필터에서 직접 사용하지 않음 (SuccessHandler 역할)

    public RestAuthenticationFilter(AuthenticationManager authenticationManager,
                                    ContextPersistence contextPersistence,
                                    MfaPolicyProvider mfaPolicyProvider,
                                    RequestMatcher requestMatcher,
                                    // String mfaInitiateUrl, // 제거 또는 SuccessHandler로 이전
                                    ApplicationContext applicationContext,
                                    @Nullable AuthenticationSuccessHandler successHandler,
                                    @Nullable AuthenticationFailureHandler failureHandler) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(contextPersistence, "contextPersistence cannot be null");
        Assert.notNull(mfaPolicyProvider, "mfaPolicyProvider cannot be null");
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        // Assert.hasText(mfaInitiateUrl, "mfaInitiateUrl cannot be empty"); // 제거
        Assert.notNull(applicationContext, "applicationContext cannot be null");

        this.authenticationManager = authenticationManager;
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.requestMatcher = requestMatcher;
        // this.mfaInitiateUrl = mfaInitiateUrl;
        this.applicationContext = applicationContext;

        this.successHandler = (successHandler != null) ? successHandler : defaultSuccessHandler();
        this.failureHandler = (failureHandler != null) ? failureHandler : defaultFailureHandler();
    }

    private AuthenticationSuccessHandler defaultSuccessHandler() {
        return (request, response, authentication) -> {
            log.warn("RestAuthenticationFilter: Using default success handler. MFA flow might not be initiated correctly if required. " +
                    "Consider injecting a specific MFA-aware success handler (e.g., PrimaryAuthenticationSuccessHandler or MfaCapableRestSuccessHandler).");
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> body = new HashMap<>();
            body.put("status", "SUCCESS_NO_MFA_HANDLED_BY_DEFAULT");
            body.put("message", "Primary authentication successful. Default handler: No MFA check or token issuance implemented here.");
            body.put("username", authentication.getName());
            mapper.writeValue(response.getWriter(), body);
        };
    }

    private AuthenticationFailureHandler defaultFailureHandler() {
        return (request, response, exception) -> {
            log.warn("RestAuthenticationFilter: Using default failure handler for exception: {}", exception.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> body = Map.of(
                    "timestamp", System.currentTimeMillis(),
                    "status", HttpServletResponse.SC_UNAUTHORIZED,
                    "error", "Unauthorized",
                    "message", exception.getMessage() != null ? exception.getMessage() : "Authentication failed."
            );
            mapper.writeValue(response.getWriter(), body);
        };
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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        log.debug("RestAuthenticationFilter: Processing primary authentication request for {}", request.getRequestURI());

        try {
            Authentication authResult = attemptAuthentication(request);
            successfulAuthentication(request, response, filterChain, authResult);
        } catch (AuthenticationException ex) {
            log.warn("RestAuthenticationFilter: Primary authentication attempt failed for {}: {}", request.getRequestURI(), ex.getMessage());
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    protected Authentication attemptAuthentication(HttpServletRequest request)
            throws AuthenticationException, IOException {
        LoginRequest loginRequest;
        try {
            loginRequest = mapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (IOException e) {
            log.error("RestAuthenticationFilter: Failed to parse login request body.", e);
            throw new AuthenticationServiceException("Failed to parse login request body.", e);
        }

        if (loginRequest.username() == null || loginRequest.password() == null) {
            log.warn("RestAuthenticationFilter: Username or password not provided in login request.");
            throw new BadCredentialsException("Username and password must be provided.");
        }

        UsernamePasswordAuthenticationToken authRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
        authRequest.setDetails(new WebAuthenticationDetails(request));
        return this.authenticationManager.authenticate(authRequest);
    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        log.info("RestAuthenticationFilter: Primary authentication successful for user: {}", authentication.getName());

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        contextPersistence.deleteContext(request); // 이전 MFA 세션 정리

        FactorContext mfaCtx = new FactorContext(authentication);
        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            deviceId = getOrCreateDeviceId(request);
        }
        mfaCtx.setAttribute("deviceId", deviceId);

        // MfaPolicyProvider 호출 (mfaFlowConfig 인자 없이)
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);

        // currentProcessingFactor에 대한 Options 설정
        AuthType currentProcessingFactor = mfaCtx.getCurrentProcessingFactor();
        if (currentProcessingFactor != null) {
            AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
            if (mfaFlowConfig != null && mfaFlowConfig.getRegisteredFactorOptions() != null) {
                AuthenticationProcessingOptions factorOptions = mfaFlowConfig.getRegisteredFactorOptions().get(currentProcessingFactor);
                mfaCtx.setCurrentFactorOptions(factorOptions);
                if (factorOptions == null) {
                    log.warn("RestAuthenticationFilter: No AuthenticationProcessingOptions found for currentProcessingFactor {} in MFA flow config for user {}.",
                            currentProcessingFactor, authentication.getName());
                }
            } else {
                log.warn("RestAuthenticationFilter: MFA FlowConfig or registeredFactorOptions not found. Cannot set currentFactorOptions for user {}.", authentication.getName());
            }
        }

        contextPersistence.saveContext(mfaCtx, request);
        log.debug("RestAuthenticationFilter: Saved FactorContext (ID: {}) for user {} with initial MFA state: {}, current factor: {}, current options: {}",
                mfaCtx.getMfaSessionId(), authentication.getName(), mfaCtx.getCurrentState(),
                mfaCtx.getCurrentProcessingFactor(), mfaCtx.getCurrentFactorOptions() != null ? mfaCtx.getCurrentFactorOptions().getClass().getSimpleName() : "null");

        this.successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException exception) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        contextPersistence.deleteContext(request);
        this.failureHandler.onAuthenticationFailure(request, response, exception);
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> "mfa".equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);
            }
        } catch (Exception e) {
            log.warn("RestAuthenticationFilter: Could not retrieve PlatformConfig or find MFA flow configuration: {}", e.getMessage());
        }
        return null;
    }

    private String getOrCreateDeviceId(HttpServletRequest request) {
        // 실제 구현에서는 더 견고한 방법 사용 (예: 세션 ID 기반, 암호화된 쿠키 등)
        String deviceId = UUID.randomUUID().toString();
        log.debug("RestAuthenticationFilter: Generated new deviceId: {}", deviceId);
        return deviceId;
    }
}