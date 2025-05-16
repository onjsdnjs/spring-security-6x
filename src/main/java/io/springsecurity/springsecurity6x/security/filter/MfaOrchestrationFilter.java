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
        // 1차 인증 성공 후 FactorContext가 생성된 이후의 MFA 관련 경로만 매칭
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher("/mfa/select-factor"),      // GET (페이지 로드), POST (선택 제출 API - 현재는 JS가 API 호출 후 페이지 이동)
                new AntPathRequestMatcher("/mfa/verify/**"),        // GET (페이지 로드)
                new AntPathRequestMatcher("/api/mfa/select-factor", "POST"), // 사용자가 Factor 선택 API
                new AntPathRequestMatcher("/api/mfa/challenge", "POST"),     // Factor 챌린지 요청 API (예: OTT 재전송, Passkey 옵션 요청)
                // 실제 Factor 검증 제출은 각 Factor 인증 필터(예: /login/mfa-ott)가 처리하고,
                // 그 성공/실패 핸들러에서 이 필터가 다시 동작할 수 있는 상태로 만들거나,
                // MfaStepFilterWrapper를 통해 Factor 인증 필터가 직접 호출됨.
                // 따라서 이 필터가 직접 /login/mfa-ott 같은 경로를 매칭할 필요는 없을 수 있음.
                // 핵심은 "상태 전이가 필요한 API 호출" 시점에 이 필터가 동작하는 것.
                new AntPathRequestMatcher("/api/mfa/verify", "POST") // 범용적인 verify 엔드포인트 (덜 권장)
        );
        log.info("MfaOrchestrationFilter initialized with default request matchers focusing on MFA progression URLs (e.g., /mfa/select-factor, /api/mfa/**).");
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
            // 이 필터가 매칭되는 URL은 FactorContext가 세션에 존재해야 하는 시점임.
            // (즉, 1차 인증 성공 후 success handler에서 FactorContext를 생성하고 저장한 후)
            log.warn("MfaOrchestrationFilter: No FactorContext found for MFA request: {}. This indicates an invalid or expired MFA session, or a misconfiguration in the authentication flow (FactorContext not saved after 1st auth).", req.getRequestURI());
            WebUtil.writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "MFA_SESSION_NOT_FOUND", "MFA session not found or expired. Please start the authentication process again.");
            return;
        }

        MfaState currentState = ctx.getCurrentState();
        log.debug("Current MFA State: {}, Session ID: {}", currentState, ctx.getMfaSessionId());

        if (currentState != null && currentState.isTerminal()) {
            log.debug("MFA state {} for session {} is terminal. Orchestration filter will not process further state transitions.", currentState, ctx.getMfaSessionId());
            chain.doFilter(req, res); // 터미널 상태면 다음 필터로 (예: 최종 응답 처리)
            return;
        }

        try {
            MfaEvent event = MfaEventPolicyResolver.resolve(req, ctx); // 요청으로부터 현재 컨텍스트에 맞는 MFA 이벤트를 해석
            log.debug("Resolved MFA Event: {} for state: {} (Session: {})", event, currentState, ctx.getMfaSessionId());

            MfaState nextState = stateMachine.nextState(currentState, event); // 상태 머신을 통해 다음 상태 결정
            log.debug("StateMachineManager proposed next state: {} from {} on event {} (Session: {})",
                    nextState, currentState, event, ctx.getMfaSessionId());

            if (currentState != nextState) { // 상태가 실제로 변경된 경우
                ctx.changeState(nextState);    // FactorContext 내부 상태 업데이트 (타임스탬프, 버전 등 관리)
                ctxPersistence.saveContext(ctx, req); // 변경된 컨텍스트를 세션 등에 다시 저장
                log.info("MFA state successfully transitioned: {} -> {} for Session ID: {} via event {}",
                        currentState, nextState, ctx.getMfaSessionId(), event);
            } else {
                log.debug("MFA event {} did not cause a state change from {}. Session ID: {}.",
                        event, currentState, ctx.getMfaSessionId());
                // 상태 변경이 없었더라도 FactorContext의 다른 속성(예: 시도 횟수)이 변경되었을 수 있으므로 저장할 수 있음
                // ctxPersistence.saveContext(ctx, req); // 필요하다면 항상 저장
            }

            // 상태 전이 후, 실제 인증 로직(예: Passkey 필터, OTT 필터)이나
            // 사용자에게 다음 단계를 안내하는 로직(예: MfaContinuationHandler 또는 다음 필터가 처리)이 실행되어야 함.
            // 이 필터는 주로 상태 전이만 담당하고, 다음 필터(MfaStepFilterWrapper 또는 각 인증 필터)가
            // 새로운 상태에 기반하여 실제 작업을 수행하도록 체인을 계속 진행.
            // 특정 상태(예: FACTOR_CHALLENGE_INITIATED)에서는 ChallengeRouter를 통해 클라이언트에 챌린지 정보를 내려줄 수도 있음.
            // (이 부분은 MfaStepBasedSuccessHandler 나 MfaCapableRestSuccessHandler와 같은 성공 핸들러에서 처리하거나,
            //  또는 특정 MfaState를 처리하는 전용 Controller/Handler에서 담당할 수 있음)

        } catch (InvalidTransitionException e) {
            log.warn("MFA InvalidTransitionException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_CONFLICT, "INVALID_MFA_TRANSITION_ORCH", e.getMessage());
            return; // 오류 발생 시 필터 체인 중단
        } catch (AuthenticationException e) {
            log.warn("MFA AuthenticationException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "MFA_AUTH_FAILURE_ORCH", e.getMessage());
            return;
        } catch (IllegalArgumentException e) { // MfaEventPolicyResolver 등에서 발생 가능
            log.warn("MFA IllegalArgumentException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_BAD_REQUEST, "MFA_INVALID_INPUT_ORCH", e.getMessage());
            return;
        } catch (Exception e) {
            log.error("Unexpected error in MfaOrchestrationFilter for Session ID: {}", ctx.getMfaSessionId(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_ORCHESTRATION_ERROR", "An unexpected server error occurred during MFA orchestration.");
            return;
        }

        if (!res.isCommitted()) {
            chain.doFilter(req, res);
        } else {
            log.debug("Response already committed after MFA orchestration for session {}. URI: {}", ctx.getMfaSessionId(), req.getRequestURI());
        }
    }
}


