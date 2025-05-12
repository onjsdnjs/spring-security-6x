package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaStateHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.StateHandlerRegistry;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        FactorContext ctx = ctxPersistence.loadOrInit(request);
        MfaState current = ctx.currentState();
        MfaEvent event = resolveEvent(request);

        try {
            MfaStateHandler handler = stateHandlerRegistry.get(current);
            if (handler == null) {
                throw new IllegalStateException("Handler not found for state: " + current);
            }

            MfaState next = handler.handleEvent(event, ctx);
            ctx.currentState(next);
            ctx.incrementVersion();
            ctxPersistence.save(ctx);

        } catch (InvalidTransitionException | IllegalStateException e) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            response.setContentType("application/json");
            mapper.writeValue(response.getWriter(), Map.of(
                    "error", "INVALID_STEP",
                    "message", e.getMessage()
            ));
            return;
        }

        filterChain.doFilter(request, response);
    }

    private MfaEvent resolveEvent(HttpServletRequest request) {
        return "GET".equalsIgnoreCase(request.getMethod())
                ? MfaEvent.REQUEST_CHALLENGE
                : MfaEvent.SUBMIT_CREDENTIAL;
    }
}


