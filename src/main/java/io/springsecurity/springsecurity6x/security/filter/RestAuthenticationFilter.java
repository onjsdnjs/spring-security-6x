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
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
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

    public RestAuthenticationFilter(AuthenticationManager authenticationManager,
                                    ContextPersistence contextPersistence,
                                    ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.contextPersistence = contextPersistence;

        // State Machine 통합자 초기화
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
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

        // 기존 FactorContext가 있다면 삭제
        FactorContext existingContext = contextPersistence.contextLoad(request);
        if (existingContext != null) {
            log.debug("Clearing existing FactorContext (ID: {}) on new primary authentication for user: {}",
                    existingContext.getMfaSessionId(), authentication.getName());

            // State Machine도 해제
            if (existingContext.getMfaSessionId() != null) {
                stateMachineIntegrator.releaseStateMachine(existingContext.getMfaSessionId());
            }

            contextPersistence.deleteContext(request);
        }

        String mfaSessionId = UUID.randomUUID().toString();
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

        // Context 저장
        contextPersistence.saveContext(factorContext, request);

        // State Machine 초기화
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
            contextPersistence.saveContext(factorContext, request);
        }

        successHandler.onAuthenticationSuccess(request, response, authentication);
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