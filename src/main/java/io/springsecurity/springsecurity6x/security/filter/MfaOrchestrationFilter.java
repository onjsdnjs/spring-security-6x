package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.MfaEventPolicyResolver;
import io.springsecurity.springsecurity6x.security.core.mfa.StateMachineManager;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
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
    private final RequestMatcher requestMatcher;

    public MfaOrchestrationFilter(ContextPersistence persistence, StateMachineManager manager,
                                  RequestMatcher mfaProcessingRequestMatcher) {
        this.ctxPersistence = Objects.requireNonNull(persistence, "ContextPersistence cannot be null");
        this.stateMachine = Objects.requireNonNull(manager, "StateMachineManager cannot be null");
        this.requestMatcher = Objects.requireNonNull(mfaProcessingRequestMatcher, "mfaProcessingRequestMatcher cannot be null");
        log.info("MfaOrchestrationFilter initialized with provided request matcher: {}", mfaProcessingRequestMatcher);
    }

    public MfaOrchestrationFilter(ContextPersistence persistence, StateMachineManager manager) {
        this.ctxPersistence = Objects.requireNonNull(persistence, "ContextPersistence cannot be null");
        this.stateMachine = Objects.requireNonNull(manager, "StateMachineManager cannot be null");
        // 이 필터는 1차 인증 성공 후 FactorContext가 생성된 이후의 MFA 관련 요청만 처리해야 함.
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher("/mfa/select-factor"),      // GET (MFA 선택 페이지 로드)
                // API 호출로 MFA 단계를 진행하는 경우. 실제 Factor 검증은 각 Factor 전용 Filter에서 처리하고,
                // 이 필터는 그 전후의 상태 관리나 API를 통한 명시적 상태 변경 요청(예: factor 선택)을 처리.
                new AntPathRequestMatcher("/api/mfa/select-factor", "POST"),
                new AntPathRequestMatcher("/api/mfa/challenge", "POST") // OTT 재전송, Passkey 옵션 요청 등
                // login/mfa-ott, login/mfa-passkey 등은 MfaStepFilterWrapper가 가로채서 해당 Factor 필터로 넘김.
                // 그 결과(성공/실패)에 따라 Success/FailureHandler가 호출되고, 이 핸들러가 다음 상태를 결정하고
                // 경우에 따라 이 MfaOrchestrationFilter가 다시 동작할 수 있는 URL로 안내할 수 있음.
        );
        log.info("MfaOrchestrationFilter initialized with default request matchers for MFA progression (e.g., /mfa/select-factor, /api/mfa/**).");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }
        log.debug("MfaOrchestrationFilter processing request: {} {}", req.getMethod(), req.getRequestURI());

        FactorContext ctx = ctxPersistence.contextLoad(req);
        if (ctx == null) {
            log.warn("MfaOrchestrationFilter: No FactorContext found for MFA request: {}. This may indicate an invalid or expired MFA session, or that the 1st authentication step did not properly save the context.", req.getRequestURI());
            WebUtil.writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "MFA_SESSION_NOT_FOUND", "MFA session not found or expired. Please start the authentication process again.");
            return;
        }

        MfaState currentState = ctx.getCurrentState();
        log.debug("Current MFA State: {}, Session ID: {}", currentState, ctx.getMfaSessionId());

        if (currentState != null && currentState.isTerminal()) {
            log.debug("MFA state {} for session {} is terminal. Orchestration filter will not process further state transitions.", currentState, ctx.getMfaSessionId());
            chain.doFilter(req, res);
            return;
        }

        try {
            MfaEvent event = MfaEventPolicyResolver.resolve(req, ctx);
            log.debug("Resolved MFA Event: {} for state: {} (Session: {})", event, currentState, ctx.getMfaSessionId());

            MfaState nextState = stateMachine.nextState(currentState, event);
            log.debug("StateMachineManager proposed next state: {} from {} on event {} (Session: {})",
                    nextState, currentState, event, ctx.getMfaSessionId());

            if (currentState != nextState) {
                ctx.changeState(nextState);
                ctxPersistence.saveContext(ctx, req);
                log.info("MFA state successfully transitioned: {} -> {} for Session ID: {} via event {}",
                        currentState, nextState, ctx.getMfaSessionId(), event);
            } else {
                log.debug("MFA event {} did not cause a state change from {}. Session ID: {}.",
                        event, currentState, ctx.getMfaSessionId());
                // 상태 변경이 없더라도 컨텍스트의 다른 내용(시도 횟수 등)이 변경되었을 수 있으므로 저장
                ctxPersistence.saveContext(ctx, req);
            }

        } catch (InvalidTransitionException e) {
            log.warn("MFA InvalidTransitionException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_CONFLICT, "INVALID_MFA_TRANSITION_ORCH", e.getMessage());
            return;
        } catch (AuthenticationException e) {
            log.warn("MFA AuthenticationException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "MFA_AUTH_FAILURE_ORCH", e.getMessage());
            return;
        } catch (IllegalArgumentException e) {
            log.warn("MFA IllegalArgumentException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_BAD_REQUEST, "MFA_INVALID_INPUT_ORCH", e.getMessage());
            return;
        } catch (Exception e) {
            log.error("Unexpected error in MfaOrchestrationFilter for Session ID: {}", ctx.getMfaSessionId(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_ORCHESTRATION_ERROR", "An unexpected server error occurred during MFA orchestration.");
            return;
        }

        // MfaOrchestrationFilter는 상태 전이 후, 클라이언트가 다음 행동을 하거나 (예: API 응답에 따른 JS 동작)
        // 또는 다른 필터(예: MfaStepFilterWrapper를 통해 실제 인증 필터)가 요청을 처리하도록 체인을 계속 진행.
        // 만약 특정 상태(예: FACTOR_CHALLENGE_INITIATED)에서 ChallengeRouter를 통해 직접 응답을 생성하고 싶다면
        // 해당 로직을 여기에 추가하거나, 전용 핸들러/컨트롤러에서 처리하도록 할 수 있음.
        // 현재 설계에서는 이 필터는 주로 상태 변경에 집중하고, 실제 응답 생성이나 인증 처리 위임은
        // 성공/실패 핸들러 또는 MfaStepFilterWrapper 등을 통해 이루어짐.
        if (!res.isCommitted()) {
            chain.doFilter(req, res);
        } else {
            log.debug("Response already committed after MFA orchestration for session {}. URI: {}", ctx.getMfaSessionId(), req.getRequestURI());
        }
    }
}


