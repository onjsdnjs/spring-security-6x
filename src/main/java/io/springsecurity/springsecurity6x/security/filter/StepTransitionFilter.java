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
import io.springsecurity.springsecurity6x.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

public class StepTransitionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(StepTransitionFilter.class);

    private final ContextPersistence ctxPersistence;
    private final StateHandlerRegistry stateHandlerRegistry;
    private final ObjectMapper mapper = new ObjectMapper(); // JSON 응답 생성 시 사용

    // RequestMatcher는 이 필터가 어떤 요청에 대해 동작할지를 결정합니다.
    // MFA 흐름과 관련된 다양한 엔드포인트를 포함하도록 설정해야 합니다.
    private final RequestMatcher requestMatcher;

    // 생성자에서 RequestMatcher를 주입받아 유연성을 높입니다.
    public StepTransitionFilter(ContextPersistence ctxPersistence,
                                StateHandlerRegistry stateHandlerRegistry,
                                RequestMatcher mfaProcessingRequestMatcher) {
        this.ctxPersistence = Objects.requireNonNull(ctxPersistence, "ContextPersistence cannot be null");
        this.stateHandlerRegistry = Objects.requireNonNull(stateHandlerRegistry, "StateHandlerRegistry cannot be null");
        this.requestMatcher = Objects.requireNonNull(mfaProcessingRequestMatcher, "mfaProcessingRequestMatcher cannot be null");
        log.info("StepTransitionFilter initialized with provided request matcher.");
    }

    // 기본 생성자 (업로드된 코드의 생성자 유지, Matcher는 내부에서 기본값으로 설정)
    // 이 생성자를 사용하는 경우, requestMatcher가 새로운 MFA 흐름에 맞게 충분히 넓은 범위를 커버해야 합니다.
    public StepTransitionFilter(ContextPersistence ctxPersistence,
                                StateHandlerRegistry stateHandlerRegistry) {
        this.ctxPersistence = Objects.requireNonNull(ctxPersistence, "ContextPersistence cannot be null");
        this.stateHandlerRegistry = Objects.requireNonNull(stateHandlerRegistry, "StateHandlerRegistry cannot be null");
        // 기본 RequestMatcher: MFA 상태 전이가 일어날 수 있는 주요 엔드포인트들.
        // 새로운 MFA 흐름에서는 이 Matcher가 더욱 세밀하게 조정되거나 외부에서 주입되어야 합니다.
        // 예를 들어, 1차 인증 성공 후 MFA 상태가 시작되므로, 1차 인증 URL도 포함될 수 있습니다.
        // 또한 각 Factor 제출 URL도 포함되어야 합니다.
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher("/api/auth/login", "POST"),      // 1차 인증 성공 후 이 필터가 동작해야 함
                new AntPathRequestMatcher("/api/mfa/select", "POST"),     // 예: 사용자가 MFA 방법 선택
                new AntPathRequestMatcher("/api/mfa/challenge", "POST"),  // 예: Factor 챌린지 요청
                new AntPathRequestMatcher("/api/mfa/verify", "POST")      // 예: Factor 검증 제출 (더 구체적으로 /api/mfa/verify/{factorType})
                // 기존: new AntPathRequestMatcher("/login/ott", "POST"),
                // 기존: new AntPathRequestMatcher("/login/webauthn", "POST")
        );
        log.info("StepTransitionFilter initialized with default request matchers. Consider providing a specific matcher.");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("StepTransitionFilter processing request: {} {}", request.getMethod(), request.getRequestURI());

        FactorContext ctx = ctxPersistence.contextLoad(request);
        if (ctx == null) {
            log.warn("FactorContext could not be loaded from ContextPersistence for request: {}. This may indicate a session issue or misconfiguration.", request.getRequestURI());
            WebUtil.writeError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONTEXT_UNAVAILABLE", "MFA context could not be loaded.");
            return;
        }

        MfaState currentState = ctx.getCurrentState();
        log.debug("Current MFA State: {}, Session ID: {}", currentState, ctx.getMfaSessionId());

        // MfaState enum에 isTerminal() 메소드가 정의되어 있다고 가정
        if (currentState != null && currentState.isTerminal()) {
            log.debug("MFA state {} for session {} is terminal. Proceeding with filter chain.", currentState, ctx.getMfaSessionId());
            chain.doFilter(request, response);
            return;
        }

        MfaEvent event;
        try {
            // MfaEventPolicyResolver는 현재 MfaEvent enum에 정의된 이벤트만 반환해야 함
            event = MfaEventPolicyResolver.resolve(request, ctx);
            log.debug("Resolved MFA Event: {} for session {}", event, ctx.getMfaSessionId());
        } catch (IllegalArgumentException e) {
            log.warn("Could not resolve MFA event for request: {} (Session: {}). Error: {}", request.getRequestURI(), ctx.getMfaSessionId(), e.getMessage());
            WebUtil.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "INVALID_MFA_EVENT_INPUT", e.getMessage());
            return;
        }

        MfaStateHandler handler = stateHandlerRegistry.get(currentState);
        if (handler == null) {
            log.error("No MfaStateHandler found for current state: {} (Session: {})", currentState, ctx.getMfaSessionId());
            WebUtil.writeError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "NO_MFA_STATE_HANDLER", "No handler configured for the current MFA state: " + currentState);
            return;
        }

        log.debug("Using MfaStateHandler: {} for state: {} (Session: {})", handler.getClass().getSimpleName(), currentState, ctx.getMfaSessionId());

        try {
            MfaState nextState = handler.handleEvent(event, ctx);
            log.debug("MfaStateHandler {} proposed next state: {} from {} on event {} (Session: {})",
                    handler.getClass().getSimpleName(), nextState, currentState, event, ctx.getMfaSessionId());

            if (nextState == null) {
                log.error("MfaStateHandler {} returned null as next state for event {} in state {} (Session: {}).",
                        handler.getClass().getSimpleName(), event, currentState, ctx.getMfaSessionId());
                WebUtil.writeError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "NULL_NEXT_MFA_STATE", "State handler returned null next state.");
                return;
            }

            // 상태가 실제로 변경된 경우에만 컨텍스트를 저장하고 로그를 남깁니다.
            if (currentState != nextState) {
                // FactorContext의 상태 변경 API 사용 (예: changeState)
                // 이 메소드는 내부적으로 버전 관리 및 타임스탬프 업데이트를 수행한다고 가정합니다.
                ctx.changeState(nextState); // 이 메소드가 FactorContext에 정의되어 있다고 가정
                ctxPersistence.saveContext(ctx);
                log.info("MFA State successfully transitioned: {} -> {} for Session ID: {}", currentState, nextState, ctx.getMfaSessionId());
            } else {
                log.debug("No state change from {}. Event {} did not cause a transition for session {}.", currentState, event, ctx.getMfaSessionId());
            }

        } catch (InvalidTransitionException | IllegalStateException e) {
            log.warn("Invalid MFA transition or illegal state for Session ID: {}. Current: {}, Event: {}. Error: {}",
                    ctx.getMfaSessionId(), currentState, event, e.getMessage(), e); // 예외 스택 트레이스 로깅 추가
            WebUtil.writeError(response, HttpServletResponse.SC_CONFLICT, "INVALID_MFA_TRANSITION", e.getMessage());
            return;
        } catch (Exception e) {
            log.error("Unexpected error during MFA step transition for Session ID: {}. Current: {}, Event: {}.",
                    ctx.getMfaSessionId(), currentState, event, e);
            WebUtil.writeError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_UNEXPECTED_ERROR", "An unexpected error occurred during MFA processing.");
            return;
        }

        if (!response.isCommitted()) {
            chain.doFilter(request, response);
        } else {
            log.debug("Response already committed after MFA state transition for session {}. URI: {}", ctx.getMfaSessionId(), request.getRequestURI());
        }
    }
}

