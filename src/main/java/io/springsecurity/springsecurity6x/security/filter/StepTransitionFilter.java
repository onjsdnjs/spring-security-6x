package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.MfaEventPolicyResolver;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaStateHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.StateHandlerRegistry;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import io.springsecurity.springsecurity6x.security.utils.AuthUtil;
import io.springsecurity.springsecurity6x.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class StepTransitionFilter extends OncePerRequestFilter {

    private final ContextPersistence ctxPersistence;
    private final StateHandlerRegistry stateHandlerRegistry;
    private final ObjectMapper mapper = new ObjectMapper();
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/auth/mfa/**");

    public StepTransitionFilter(ContextPersistence ctxPersistence,
                                StateHandlerRegistry stateHandlerRegistry) {
        this.ctxPersistence = ctxPersistence;
        this.stateHandlerRegistry = stateHandlerRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        FactorContext ctx = ctxPersistence.contextLoad(request);
        MfaState currentState = ctx.currentState();
        MfaEvent event = MfaEventPolicyResolver.resolve(request, ctx);

        // TOKEN_ISSUANCE 상태에서는 필터 실행 불필요
        if (AuthUtil.isTerminalState(currentState)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            MfaStateHandler handler = stateHandlerRegistry.get(currentState);
            if (handler == null) {
                response.sendError(409, "현재 상태에 대한 핸들러가 존재하지 않습니다.");
                return;
            }

            MfaState next = handler.handleEvent(event, ctx);

            if (!ctx.tryTransition(currentState, next)) {
                WebUtil.writeError(response, 409, "INVALID_STEP", "잘못된 상태 전이입니다.");
                return;
            }

            ctx.currentState(next);
            ctx.incrementVersion();
            ctxPersistence.saveContext(ctx);

        } catch (InvalidTransitionException | IllegalStateException e) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            response.setContentType("application/json");
            mapper.writeValue(response.getWriter(), Map.of(
                    "error", "INVALID_STEP",
                    "message", e.getMessage()
            ));
            return;
        }

        chain.doFilter(request, response);
    }
}


