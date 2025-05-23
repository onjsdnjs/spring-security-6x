package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
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
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/auth/login", "POST");
    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
            new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final AuthenticationManager authenticationManager;
    private final ContextPersistence contextPersistence;
    private final ApplicationContext applicationContext;


    public RestAuthenticationFilter(AuthenticationManager authenticationManager, ContextPersistence contextPersistence,
                                    ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.contextPersistence = contextPersistence;
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

        try {
            Authentication authResult = attemptAuthentication(request, response);
            if (authResult == null) {
                filterChain.doFilter(request, response);
                return;
            }

            successfulAuthentication(request, response, filterChain, authResult);

        } catch (AuthenticationException ex) {
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    private Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            LoginRequest login = mapper.readValue(request.getInputStream(), LoginRequest.class);
            UsernamePasswordAuthenticationToken authRequest =
                    new UsernamePasswordAuthenticationToken(login.username(), login.password());
            return authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            throw new RuntimeException("Authentication request body read failed", e);
        }
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // 기존 FactorContext가 있다면 삭제 (1차 인증은 항상 새로운 MFA 세션 시작 또는 단일 인증 완료로 간주)
        FactorContext existingContext = contextPersistence.contextLoad(request);
        if (existingContext != null) {
            log.debug("Clearing existing FactorContext (ID: {}) on new primary authentication for user: {}",
                    existingContext.getMfaSessionId(), authentication.getName());
            contextPersistence.deleteContext(request);
        }

        String mfaSessionId = UUID.randomUUID().toString();
        // 1차 인증 성공 시점에서는 flowTypeName을 아직 확정하지 않거나, 'primary' 로 설정.
        // UnifiedAuthenticationSuccessHandler 에서 MFA 필요 여부에 따라 'mfa'로 설정하거나,
        // 단일 인증으로 처리.
        String flowTypeNameForContext = AuthType.MFA.name().toLowerCase(); // 또는 null

        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication, // 인증된 Authentication 객체
                MfaState.PRIMARY_AUTHENTICATION_COMPLETED, // 1차 인증 완료 상태
                flowTypeNameForContext // 초기 flowTypeName (SuccessHandler 에서 MFA 여부에 따라 변경될 수 있음)
        );

        String deviceId = getOrCreateDeviceId(request);
        factorContext.setAttribute("deviceId", deviceId);
        // FactorContext에 registeredMfaFactors 설정은 MfaPolicyProvider가 evaluate 시 수행하도록 함.

        contextPersistence.saveContext(factorContext, request);
        log.info("FactorContext (ID: {}) created and saved after primary authentication for user: {}. Initial state: {}, FlowType: {}",
                factorContext.getMfaSessionId(), factorContext.getUsername(), factorContext.getCurrentState(), factorContext.getFlowTypeName());

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
        AuthenticationStepConfig currentFactorJustCompleted = mfaFlowConfig.getStepConfigs().stream()
                .findFirst()
                .orElse(null);

        factorContext.addCompletedFactor(currentFactorJustCompleted);

        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {

        if (!AuthType.MFA.name().equalsIgnoreCase(flowTypeName)) { // MFA 플로우만 처리
            log.warn("Attempting to find non-MFA flow config in MfaFactorProcessingSuccessHandler: {}", flowTypeName);
            return null;
        }
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
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

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        contextPersistence.deleteContext(request);
        failureHandler.onAuthenticationFailure(request, response, failed);
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