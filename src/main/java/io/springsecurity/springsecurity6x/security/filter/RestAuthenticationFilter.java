package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
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
import jakarta.servlet.http.HttpSession;
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
import java.util.*;

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

    public RestAuthenticationFilter(AuthenticationManager authenticationManager,
                                    ContextPersistence contextPersistence,
                                    MfaPolicyProvider mfaPolicyProvider,
                                    RequestMatcher requestMatcher,
                                    ApplicationContext applicationContext) {
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
        this.applicationContext = applicationContext;
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

        contextPersistence.deleteContext(request);

        // FactorContext 생성 시 현재 flowTypeName 전달
        AuthenticationFlowConfig currentFlow = findCurrentFlowConfig(request); // 현재 요청에 매칭된 FlowConfig를 찾는 로직 필요
        String flowTypeNameForContext = (currentFlow != null && currentFlow.getTypeName() != null) ?
                currentFlow.getTypeName() : "unknown_flow"; // 기본값 또는 예외처리

        FactorContext mfaCtx = new FactorContext(authentication, flowTypeNameForContext); // flowTypeName 전달
        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            deviceId = getOrCreateDeviceId(request); // 이 메소드는 프로젝트 내에 존재한다고 가정
        }
        mfaCtx.setAttribute("deviceId", deviceId);

        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);

        // currentProcessingFactor에 대한 Options 설정
        AuthType currentProcessingFactor = mfaCtx.getCurrentProcessingFactor();
        if (currentProcessingFactor != null && currentFlow != null) { // currentFlow null 체크 추가
            AuthenticationProcessingOptions factorOptions = currentFlow.getRegisteredFactorOptions().get(currentProcessingFactor);
            mfaCtx.setCurrentFactorOptions(factorOptions);
            if (factorOptions == null) {
                log.warn("RestAuthenticationFilter: No AuthenticationProcessingOptions found for currentProcessingFactor {} in flow {} for user {}.",
                        currentProcessingFactor, flowTypeNameForContext, authentication.getName());
            }
            // 첫 번째 2FA 단계의 stepId 설정
            Optional<AuthenticationStepConfig> firstMfaStepOpt = currentFlow.getStepConfigs().stream()
                    .filter(s -> s.getOrder() > 0 && s.getType().equalsIgnoreCase(currentProcessingFactor.name())) // order > 0 이 2차 인증 요소
                    .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder)); // 가장 먼저 나오는 해당 타입의 스텝
            firstMfaStepOpt.ifPresent(step -> mfaCtx.setCurrentStepId(step.getStepId()));
        }

        contextPersistence.saveContext(mfaCtx, request);
        log.debug("RestAuthenticationFilter: Saved FactorContext (ID: {}, Flow: {}) for user {} with initial MFA state: {}, current factor: {}, current stepId: {}",
                mfaCtx.getMfaSessionId(), mfaCtx.getFlowTypeName(), authentication.getName(), mfaCtx.getCurrentState(),
                mfaCtx.getCurrentProcessingFactor(), mfaCtx.getCurrentStepId());

        this.successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    // findCurrentFlowConfig는 실제 HttpSecurity와 현재 요청을 매핑하여 FlowConfig를 찾는 로직 필요
// (PlatformContext 또는 HttpSecurity의 sharedObject를 통해 가져올 수 있음)
    @Nullable
    private AuthenticationFlowConfig findCurrentFlowConfig(HttpServletRequest request) {
        // 이 메소드는 현재 요청에 대해 어떤 AuthenticationFlowConfig가 매칭되는지를 결정해야 합니다.
        // 예를 들어, PlatformContext에 현재 요청을 처리하는 SecurityFilterChain과 매핑된
        // AuthenticationFlowConfig 정보를 저장해두고 가져올 수 있습니다.
        // 또는 Spring Security의 FilterChainProxy 등을 통해 현재 적용된 SecurityFilterChain을 얻고,
        // 그 SecurityFilterChain과 연관된 AuthenticationFlowConfig를 찾는 더 복잡한 메커니즘이 필요할 수 있습니다.
        // 여기서는 ApplicationContext를 통해 PlatformConfig 빈을 가져와서,
        // 요청 URI와 가장 잘 맞는 (또는 "mfa" 타입의) FlowConfig를 찾는 단순화된 예시를 사용합니다.
        // 실제로는 더 정교한 매칭 로직이 필요합니다.
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig.getFlows() != null) {
                // 예시: /api/auth/login 요청이 MFA 플로우에 속한다고 가정하고 "mfa" 타입의 플로우를 찾음
                // 실제로는 RequestMatcher를 사용하여 현재 요청 URI와 각 FlowConfig의 RequestMatcher를 비교해야 함.
                return platformConfig.getFlows().stream()
                        .filter(flow -> "mfa".equalsIgnoreCase(flow.getTypeName())) // 임시로 MFA 플로우만 고려
                        .findFirst()
                        .orElse(null);
            }
        } catch (Exception e) {
            log.warn("RestAuthenticationFilter: Could not retrieve PlatformConfig or find current flow configuration: {}", e.getMessage());
        }
        return null; // 실제로는 null을 반환하지 않도록 설계해야 함
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
            if (platformConfig.getFlows() != null) {
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
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId)) {
            return deviceId;
        }
        HttpSession session = request.getSession(true);
        deviceId = (String) session.getAttribute("transientDeviceId");
        if (!StringUtils.hasText(deviceId)) {
            deviceId = UUID.randomUUID().toString();
            session.setAttribute("transientDeviceId", deviceId);
            log.debug("Generated and stored new transient deviceId in session: {}", deviceId);
        }
        return deviceId;
    }
}