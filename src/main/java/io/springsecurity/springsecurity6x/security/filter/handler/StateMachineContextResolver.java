package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachine;

@Slf4j
@RequiredArgsConstructor
public class StateMachineContextResolver {

    private final MfaStateMachineService stateMachineService;
    private final FactorContextStateAdapter factorContextAdapter;
    private final ContextPersistence contextPersistence;

    /**
     * State Machine을 주 소스로 FactorContext를 가져옴
     */
    public FactorContext resolveContext(HttpServletRequest request) {
        String sessionId = extractSessionId(request);

        if (sessionId == null) {
            // 세션 ID가 없으면 ContextPersistence에서 시도
            return contextPersistence.contextLoad(request);
        }

        try {
            // 1. State Machine에서 가져오기 시도
            StateMachine<MfaState, MfaEvent> stateMachine =
                    stateMachineService.getStateMachine(sessionId);

            if (stateMachine != null) {
                // State Machine에서 FactorContext 추출
                FactorContext context = extractFromStateMachine(stateMachine);

                if (context != null) {
                    log.debug("FactorContext loaded from State Machine for session: {}", sessionId);
                    return context;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to load from State Machine for session: {}, falling back to persistence",
                    sessionId, e);
        }

        // 2. Fallback: ContextPersistence에서 가져오기
        FactorContext context = contextPersistence.contextLoad(request);

        // 3. State Machine과 동기화
        if (context != null && stateMachineService != null) {
            syncWithStateMachine(context, request);
        }

        return context;
    }

    /**
     * FactorContext를 State Machine과 ContextPersistence 모두에 저장
     */
    public void saveContext(FactorContext context, HttpServletRequest request) {
        // 1. State Machine에 저장
        try {
            StateMachine<MfaState, MfaEvent> stateMachine =
                    stateMachineService.getStateMachine(context.getMfaSessionId());

            if (stateMachine != null) {
                // State Machine ExtendedState 업데이트
                factorContextAdapter.updateFactorContext(stateMachine, context);
                log.debug("FactorContext saved to State Machine for session: {}",
                        context.getMfaSessionId());
            }
        } catch (Exception e) {
            log.error("Failed to save to State Machine for session: {}",
                    context.getMfaSessionId(), e);
        }

        // 2. ContextPersistence에도 저장 (백업)
        contextPersistence.saveContext(context, request);
    }

    private FactorContext extractFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        // StateContextHelper를 사용하여 추출
        StateContext<MfaState, MfaEvent> stateContext = stateMachine.getStateMachineAccessor()
                .withRegion()
                .stream()
                .findFirst()
                .map(access -> access.getStateMachine().getExtendedState())
                .orElse(null);

        if (stateContext != null) {
            return stateContextHelper.extractFactorContext(stateContext);
        }

        return null;
    }

    private void syncWithStateMachine(FactorContext context, HttpServletRequest request) {
        try {
            // State Machine이 초기화되지 않았다면 초기화
            if (!stateMachineService.isInitialized(context.getMfaSessionId())) {
                stateMachineService.initializeStateMachine(context, request);
            }

            // 현재 상태 동기화
            MfaState smState = stateMachineService.getCurrentState(context.getMfaSessionId());
            if (smState != context.getCurrentState()) {
                log.info("Syncing state from State Machine: {} -> {}",
                        context.getCurrentState(), smState);
                context.changeState(smState);
            }
        } catch (Exception e) {
            log.warn("Failed to sync with State Machine", e);
        }
    }

    private String extractSessionId(HttpServletRequest request) {
        // 1. 헤더에서 확인
        String sessionId = request.getHeader("X-MFA-Session-Id");

        // 2. 파라미터에서 확인
        if (sessionId == null) {
            sessionId = request.getParameter("mfaSessionId");
        }

        // 3. HttpSession에서 확인
        if (sessionId == null && request.getSession(false) != null) {
            sessionId = (String) request.getSession().getAttribute("mfaSessionId");
        }

        return sessionId;
    }
}
