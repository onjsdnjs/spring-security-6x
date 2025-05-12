package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.ChallengeRouter;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.StateHandlerRegistry;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
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
    private final StateHandlerRegistry handlerRegistry;
    private final ChallengeRouter router;
    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/auth/mfa", "POST");

    public MfaOrchestrationFilter(ContextPersistence persistence, StateMachineManager manager,
                                  StateHandlerRegistry registry, ChallengeRouter router) {
        this.ctxPersistence  = persistence;
        this.stateMachine    = manager;
        this.handlerRegistry = registry;
        this.router = router;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        try {

            FactorContext ctx = ctxPersistence.loadOrInit(req);
            MfaEvent ev  = deriveEvent(req, ctx);
            stateMachine.fireEvent(ctx, ev);
            ctxPersistence.save(ctx);
            chain.doFilter(req, res);

        } catch (InvalidTransitionException e) {
            // 409 JSON 에러
            router.writeError(res, 409, "INVALID_STEP", e.getMessage());
        } catch (AuthenticationException e) {
            // 인증 실패 JSON
            router.writeError(res, 401, "AUTH_FAILURE", e.getMessage());
        } catch (Exception e) {
            // 나머지 에러
            router.writeError(res, 500, "INTERNAL_ERROR", "서버 오류가 발생했습니다.");
        }
    }

    private MfaEvent deriveEvent(HttpServletRequest req, FactorContext ctx) {
        // 간단 예: GET -> REQUEST_CHALLENGE, POST -> SUBMIT_CREDENTIAL
        if ("GET".equalsIgnoreCase(req.getMethod())) {
            return MfaEvent.REQUEST_CHALLENGE;
        } else {
            return MfaEvent.SUBMIT_CREDENTIAL;
        }
    }
}

