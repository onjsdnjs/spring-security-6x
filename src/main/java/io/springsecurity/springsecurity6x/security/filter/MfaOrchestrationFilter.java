package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.ChallengeRouter;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.MfaEventPolicyResolver;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import io.springsecurity.springsecurity6x.security.utils.AuthUtil;
import io.springsecurity.springsecurity6x.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class MfaOrchestrationFilter extends OncePerRequestFilter {
    private final ContextPersistence ctxPersistence;
    private final StateMachineManager stateMachine;
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/auth/mfa", "POST");

    public MfaOrchestrationFilter(ContextPersistence persistence,
                                  StateMachineManager manager) {
        this.ctxPersistence  = persistence;
        this.stateMachine    = manager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        try {
            FactorContext ctx = ctxPersistence.contextLoad(req);

            if (AuthUtil.isTerminalState(ctx.currentState())) {
                chain.doFilter(req, res);
                return;
            }

            MfaEvent event = MfaEventPolicyResolver.resolve(req, ctx);
            MfaState next = stateMachine.nextState(ctx.currentState(), event);
            ctx.currentState(next);
            ctx.incrementVersion();
            ctxPersistence.saveContext(ctx);

        } catch (InvalidTransitionException e) {
            WebUtil.writeError(res, 409, "INVALID_STEP", e.getMessage());
            return;
        } catch (AuthenticationException e) {
            WebUtil.writeError(res, 401, "AUTH_FAILURE", e.getMessage());
            return;
        } catch (Exception e) {
            WebUtil.writeError(res, 500, "INTERNAL_ERROR", "서버 오류가 발생했습니다.");
            return;
        }

        chain.doFilter(req, res);
    }
}


