package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;

    /**
     * State Machine 초기화
     */
    public void initializeStateMachine(FactorContext ctx, HttpServletRequest request) {
        if (ctx == null || ctx.getMfaSessionId() == null) {
            log.warn("Cannot initialize State Machine without valid FactorContext");
            return;
        }

        try {
            stateMachineService.initializeStateMachine(ctx, request);
            log.info("State Machine initialized for session: {}", ctx.getMfaSessionId());
        } catch (Exception e) {
            log.error("Failed to initialize State Machine for session: {}",
                    ctx.getMfaSessionId(), e);
            throw new RuntimeException("State Machine initialization failed", e);
        }
    }

    /**
     * FactorContext와 State Machine 상태 동기화
     */
    public void syncStateWithStateMachine(FactorContext ctx, HttpServletRequest request) {
        if (ctx == null || ctx.getMfaSessionId() == null) {
            return;
        }

        try {
            MfaState currentState = stateMachineService.getCurrentState(ctx.getMfaSessionId());

            if (ctx.getCurrentState() != currentState) {
                log.debug("Syncing FactorContext state from {} to {}",
                        ctx.getCurrentState(), currentState);
                ctx.changeState(currentState);
            }
        } catch (Exception e) {
            log.error("Failed to sync state with State Machine for session: {}",
                    ctx.getMfaSessionId(), e);
        }
    }

    /**
     * State Machine에 이벤트 전송
     */
    public boolean sendEvent(MfaEvent event, FactorContext ctx, HttpServletRequest request) {
        if (ctx == null || event == null) {
            return false;
        }

        try {
            boolean accepted = stateMachineService.sendEvent(event, ctx, request);

            if (accepted) {
                log.info("Event {} accepted for session: {}", event, ctx.getMfaSessionId());
            } else {
                log.warn("Event {} rejected for session: {} in state: {}",
                        event, ctx.getMfaSessionId(), ctx.getCurrentState());
            }

            return accepted;
        } catch (Exception e) {
            log.error("Failed to send event {} for session: {}",
                    event, ctx.getMfaSessionId(), e);
            return false;
        }
    }

    /**
     * 현재 State Machine 상태 조회
     */
    public MfaState getCurrentState(String sessionId) {
        try {
            return stateMachineService.getCurrentState(sessionId);
        } catch (Exception e) {
            log.error("Failed to get current state for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    /**
     * State Machine 해제
     */
    public void releaseStateMachine(String sessionId) {
        try {
            stateMachineService.releaseStateMachine(sessionId);
            log.info("State Machine released for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to release State Machine for session: {}", sessionId, e);
        }
    }
}