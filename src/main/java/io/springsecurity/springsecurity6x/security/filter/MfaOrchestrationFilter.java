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

    // RequestMatcher는 MFA 흐름의 시작점 또는 주요 상태 변경 트리거 지점을 포함해야 함.
    // 예를 들어, 1차 인증 성공 후 또는 사용자가 MFA 관련 액션을 취하는 URL.
    private final RequestMatcher requestMatcher;

    public MfaOrchestrationFilter(ContextPersistence persistence,
                                  StateMachineManager manager,
                                  RequestMatcher mfaProcessingRequestMatcher) {
        this.ctxPersistence = Objects.requireNonNull(persistence, "ContextPersistence cannot be null");
        this.stateMachine = Objects.requireNonNull(manager, "StateMachineManager cannot be null");
        this.requestMatcher = Objects.requireNonNull(mfaProcessingRequestMatcher, "mfaProcessingRequestMatcher cannot be null");
        log.info("MfaOrchestrationFilter initialized with provided request matcher.");
    }
    // 업로드된 코드의 기존 생성자 유지 (기본 Matcher 제공)
    public MfaOrchestrationFilter(ContextPersistence persistence, StateMachineManager manager) {
        this.ctxPersistence = Objects.requireNonNull(persistence, "ContextPersistence cannot be null");
        this.stateMachine = Objects.requireNonNull(manager, "StateMachineManager cannot be null");
        this.requestMatcher = new OrRequestMatcher(
                // 1차 인증 성공 직후, MFA 상태를 시작하기 위해 이 필터가 동작해야 하는 경우가 있음.
                // 이 경우, 1차 인증 필터의 successHandler 에서 특정 attribute를 설정하고,
                // 이 필터는 해당 attribute를 확인하거나, 특정 MFA 시작 URL로 포워딩/리다이렉트 되도록 설계.
                // 현재 Matcher는 이전 버전의 URL을 포함하고 있으므로, 새로운 MFA 흐름에 맞게 조정 필요.
                // 예: new AntPathRequestMatcher("/api/mfa/initiate", "POST"), // MFA 흐름 시작
                //      new AntPathRequestMatcher("/api/mfa/select-factor", "POST") // 사용자가 Factor 선택 제출
                new AntPathRequestMatcher("/api/auth/login", "POST"), // 1차 인증 시도 후 MFA 결정
                new AntPathRequestMatcher("/api/mfa/**", "POST")      // MFA 관련 모든 POST 요청
        );
        log.info("MfaOrchestrationFilter initialized with default request matchers. Consider providing a specific matcher.");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        log.debug("MfaOrchestrationFilter processing request: {} {}", req.getMethod(), req.getRequestURI());

        FactorContext ctx = ctxPersistence.contextLoad(req);
        if (ctx == null) {
            log.warn("FactorContext could not be loaded from persistence store for request: {}. This is unexpected if the request matches MFA processing paths.", req.getRequestURI());
            WebUtil.writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONTEXT_MISSING", "MFA context could not be loaded or initialized.");
            return;
        }

        MfaState currentState = ctx.getCurrentState();
        log.debug("Current MFA State: {}, Session ID: {}", currentState, ctx.getMfaSessionId());

        // MfaState enum에 isTerminal() 메소드가 정의되어 있다고 가정
        if (currentState != null && currentState.isTerminal()) {
            log.debug("MFA state {} for session {} is terminal. Orchestration filter will not process further state transitions.", currentState, ctx.getMfaSessionId());
            chain.doFilter(req, res);
            return;
        }

        try {
            // MfaEventPolicyResolver는 현재 MfaEvent enum에 정의된 이벤트만 반환해야 함
            MfaEvent event = MfaEventPolicyResolver.resolve(req, ctx);
            log.debug("Resolved MFA Event: {} for state: {} (Session: {})", event, currentState, ctx.getMfaSessionId());

            // StateMachineManager를 사용하여 다음 상태 결정
            MfaState nextState = stateMachine.nextState(currentState, event);
            log.debug("StateMachineManager proposed next state: {} from {} on event {} (Session: {})",
                    nextState, currentState, event, ctx.getMfaSessionId());


            // FactorContext의 상태 변경 API 사용 (예: changeState 또는 compareAndSetState)
            // 여기서는 nextState로 상태를 변경하는 것을 목표로 함.
            // compareAndSetState는 동시성 제어를 위한 것이며, 일반적인 상태 변경은 changeState가 더 적합할 수 있음.
            // 업로드된 코드에서 ctx.compareAndSetState(currentState, nextState)의 반환 값 의미가
            // "전이에 성공하면 true, 실패(CAS 실패)하면 false"라고 가정합니다.
            // 따라서, 전이에 실패한 경우 (예: 다른 요청에 의해 이미 상태가 변경된 경우) 오류로 처리합니다.
            if (ctx.getCurrentState() == currentState) { // 현재 컨텍스트의 상태가 여전히 우리가 읽었던 상태인지 확인
                ctx.changeState(nextState); // FactorContext.changeState는 상태를 변경하고 내부 버전/타임스탬프 업데이트
            } else {
                // 상태가 그 사이에 변경된 경우, 이는 동시성 문제일 수 있음.
                log.warn("MFA state changed concurrently for Session ID: {}. Expected: {}, Actual: {}. Aborting transition for event {}.",
                        ctx.getMfaSessionId(), currentState, ctx.getCurrentState(), event);
                // 이 경우, 현재 요청을 오류로 처리하거나, 새로운 현재 상태를 기반으로 재시도 로직 필요.
                // 여기서는 충돌로 처리.
                WebUtil.writeError(res, HttpServletResponse.SC_CONFLICT, "CONCURRENT_STATE_CHANGE", "MFA state changed concurrently. Please retry.");
                return;
            }

            // 상태 전이 성공 시 컨텍스트 저장
            if (currentState != nextState) { // 상태가 실제로 변경된 경우
                ctxPersistence.saveContext(ctx);
                log.info("MFA state successfully transitioned: {} -> {} for Session ID: {} via event {}",
                        currentState, nextState, ctx.getMfaSessionId(), event);
            } else {
                log.debug("MFA event {} did not cause a state change from {} for Session ID: {}. Context might still be saved if modified.",
                        event, currentState, ctx.getMfaSessionId());
                // 상태 변경이 없더라도 FactorContext의 다른 속성이 변경되었을 수 있으므로 저장할 수 있음
                // ctxPersistence.saveContext(ctx); // 또는 변경된 경우에만 저장하는 로직을 ContextPersistence에 위임
            }

        } catch (InvalidTransitionException e) {
            log.warn("MFA InvalidTransitionException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_CONFLICT, "INVALID_MFA_TRANSITION_ORCH", e.getMessage());
            return;
        } catch (AuthenticationException e) { // 1차 인증 또는 Factor 인증 과정에서의 예외
            log.warn("MFA AuthenticationException for Session ID: {}: {}",ctx.getMfaSessionId(), e.getMessage(), e);
            // SecurityContextHolder.clearContext(); // 필요시
            WebUtil.writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "MFA_AUTH_FAILURE", e.getMessage());
            return;
        } catch (IllegalArgumentException e) { // MfaEventPolicyResolver 등에서 발생 가능
            log.warn("MFA IllegalArgumentException for Session ID: {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_BAD_REQUEST, "MFA_INVALID_INPUT", e.getMessage());
            return;
        } catch (Exception e) {
            log.error("Unexpected error in MfaOrchestrationFilter for Session ID: {}", ctx.getMfaSessionId(), e);
            WebUtil.writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_ORCHESTRATION_ERROR", "An unexpected server error occurred during MFA orchestration.");
            return;
        }

        // 상태 전이 후, 실제 인증 로직(예: Passkey 필터, OTT 필터)이나
        // 사용자에게 다음 단계를 안내하는 로직(예: MfaContinuationHandler)이 실행되어야 함.
        // 이 필터는 주로 상태 전이만 담당하고, 다음 필터(MfaStepFilterWrapper 또는 각 인증 필터)가
        // 새로운 상태에 기반하여 실제 작업을 수행하도록 체인을 계속 진행.
        if (!res.isCommitted()) {
            chain.doFilter(req, res);
        } else {
            log.debug("Response already committed after MFA orchestration for session {}. URI: {}", ctx.getMfaSessionId(), req.getRequestURI());
        }
    }
}


