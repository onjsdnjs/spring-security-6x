package io.springsecurity.springsecurity6x.security.filter;

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
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Slf4j
public class MfaOrchestrationFilter extends OncePerRequestFilter {
    private final ContextPersistence ctxPersistence;
    private final StateMachineManager stateMachine;
    private final RequestMatcher requestMatcher = new OrRequestMatcher(
            new AntPathRequestMatcher("/api/auth/login", "POST"),
            new AntPathRequestMatcher("/login/ott", "POST"),
            new AntPathRequestMatcher("/login/webauthn", "POST"),
            new AntPathRequestMatcher("/api/auth/mfa", "POST") // MFA 옵션 요청 등 추가 고려
    );

    public MfaOrchestrationFilter(ContextPersistence persistence, StateMachineManager manager) {
        this.ctxPersistence = Objects.requireNonNull(persistence, "ContextPersistence cannot be null");
        this.stateMachine = Objects.requireNonNull(manager, "StateMachineManager cannot be null");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        FactorContext ctx = ctxPersistence.contextLoad(req); // 여기서 Null 반환 가능성 체크 (구현에 따라)
        if (ctx == null) {
            log.warn("FactorContext could not be loaded from persistence store.");
            WebUtil.writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "CONTEXT_LOAD_FAILURE", "MFA context could not be loaded.");
            return;
        }
        if (AuthUtil.isTerminalState(ctx.getCurrentState())) {
            chain.doFilter(req, res);
            return;
        }

        try {
            MfaEvent event = MfaEventPolicyResolver.resolve(req, ctx);
            MfaState currentState = ctx.getCurrentState(); // getCurrentState() 사용
            MfaState nextState = stateMachine.nextState(currentState, event);

            // compareAndSetState가 성공하면 true를 반환. 실패하면 false.
            // 따라서 잘못된 전이(실패)는 !ctx.compareAndSetState(...) 로 체크
            if (!ctx.compareAndSetState(currentState, nextState)) {
                log.warn("Invalid MFA state transition attempted from {} to {} with event {}", currentState, nextState, event);
                WebUtil.writeError(res, HttpServletResponse.SC_CONFLICT, "INVALID_STEP", "Invalid state transition.");
                return;
            }
            // 상태 전이 성공 시 컨텍스트 저장
            // FactorContext의 compareAndSetState 내부에서 version increment 및 timestamp 업데이트 가정
            ctxPersistence.saveContext(ctx); // FactorContext의 구현에 따라 saveContext(ctx, req) 형태일 수 있음
            log.debug("MFA state transitioned from {} to {} with event {}", currentState, nextState, event);

        } catch (InvalidTransitionException e) {
            log.warn("MFA InvalidTransitionException: {}", e.getMessage());
            WebUtil.writeError(res, HttpServletResponse.SC_CONFLICT, "INVALID_STEP", e.getMessage());
            return;
        } catch (AuthenticationException e) {
            log.warn("MFA AuthenticationException: {}", e.getMessage());
            // SecurityContextHolder.clearContext(); // 인증 실패 시 컨텍스트 클리어 고려
            WebUtil.writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "AUTH_FAILURE", e.getMessage());
            return;
        } catch (Exception e) { // 좀 더 구체적인 예외 처리 권장
            log.error("Unexpected error in MfaOrchestrationFilter", e);
            WebUtil.writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected server error occurred during MFA processing.");
            return;
        }

        chain.doFilter(req, res);
    }
}


