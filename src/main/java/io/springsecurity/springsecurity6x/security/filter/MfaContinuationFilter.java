package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaRequestHandler;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
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

        // 요청 핸들러 초기화
        this.requestHandler = new MfaRequestHandler(
                contextPersistence, mfaPolicyProvider, authContextProperties,
                responseWriter, applicationContext, urlMatcher
        );

        log.info("MfaContinuationFilter initialized with URLs: {}", urlMatcher.getConfiguredUrls());
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
            requestHandler.handleInvalidContext(request, response);
            return;
        }

        MfaState currentState = ctx.getCurrentState();

        if (currentState.isTerminal()) {
            requestHandler.handleTerminalContext(request, response, ctx);
            return;
        }

        try {
            MfaRequestType requestType = urlMatcher.getRequestType(request);

            // 요청 처리
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
}