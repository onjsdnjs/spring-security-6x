package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class StepTransitionFilter extends OncePerRequestFilter {
    private final ContextPersistence ctxPersistence;
    private final StateMachineManager stateMachine;
    private final ObjectMapper mapper = new ObjectMapper();

    public StepTransitionFilter(ContextPersistence ctxPersistence,
                                StateMachineManager stateMachine) {
        this.ctxPersistence = ctxPersistence;
        this.stateMachine   = stateMachine;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {

        FactorContext ctx = ctxPersistence.loadOrInit(req);
        MfaEvent event = deriveEvent(req);
        try {
            stateMachine.fireEvent(ctx, event);
        } catch (InvalidTransitionException e) {
            res.setStatus(HttpServletResponse.SC_CONFLICT);
            res.setContentType("application/json");
            mapper.writeValue(res.getWriter(), Map.of(
                    "error", "INVALID_STEP",
                    "message", e.getMessage()
            ));
            return;
        }
        ctxPersistence.save(ctx);
        chain.doFilter(req, res);
    }

    private MfaEvent deriveEvent(HttpServletRequest req) {
        return "GET".equalsIgnoreCase(req.getMethod())
                ? MfaEvent.REQUEST_CHALLENGE
                : MfaEvent.SUBMIT_CREDENTIAL;
    }
}
