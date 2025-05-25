package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaRequestHandler;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaRequestHandlerWithStateMachine;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final RequestMatcher requestMatcher;
    private final MfaRequestHandler requestHandler;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public MfaContinuationFilter(ContextPersistence contextPersistence,
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.applicationContext = Objects.requireNonNull(applicationContext);

        // URL 매처 초기화
        this.urlMatcher = new MfaUrlMatcher(authContextProperties, applicationContext);
        this.requestMatcher = urlMatcher.createRequestMatcher();

        // State Machine 통합자 초기화 (빈으로 가져오기)
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        // 요청 핸들러 초기화 - State Machine 통합자 추가
        this.requestHandler = new MfaRequestHandlerWithStateMachine(
                contextPersistence, mfaPolicyProvider, authContextProperties,
                responseWriter, applicationContext, urlMatcher, stateMachineIntegrator
        );

        log.info("MfaContinuationFilter initialized with State Machine integration");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!urlMatcher.isMfaRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing request: {} {}",
                request.getMethod(), request.getRequestURI());

        FactorContext ctx = contextPersistence.contextLoad(request);
        if (!isValidMfaContext(ctx)) {
            handleInvalidContext(request, response);
            return;
        }

        // State Machine 초기화 및 동기화
        stateMachineIntegrator.syncStateWithStateMachine(ctx, request);

        if (ctx.getCurrentState().isTerminal()) {
            requestHandler.handleTerminalContext(request, response, ctx);
            return;
        }

        try {
            MfaRequestType requestType = urlMatcher.getRequestType(request);

            // State Machine 통합된 요청 처리
            requestHandler.handleRequest(requestType, request, response, ctx, filterChain);

        } catch (Exception e) {
            requestHandler.handleGenericError(request, response, ctx, e);
        }
    }

    private boolean isValidMfaContext(FactorContext ctx) {
        return ctx != null &&
                ctx.getMfaSessionId() != null &&
                "MFA".equalsIgnoreCase(ctx.getFlowTypeName());
    }

    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        log.warn("Invalid MFA context for request: {}", request.getRequestURI());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA 세션이 유효하지 않습니다.");
        errorResponse.put("redirectUrl", request.getContextPath() + "/loginForm");

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다.",
                request.getRequestURI(), errorResponse);
    }
}