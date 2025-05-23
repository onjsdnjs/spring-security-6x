package io.springsecurity.springsecurity6x.security.statemachine.listener;

import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.transition.Transition;
import org.springframework.stereotype.Component;

/**
 * MFA State 변경 리스너 구현체
 */
@Slf4j
@Component
public class MfaStateChangeListener extends StateMachineListenerAdapter<MfaState, MfaEvent>
        implements MfaStateMachineListener {

    @Override
    public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
        MfaState fromState = from != null ? from.getId() : null;
        MfaState toState = to != null ? to.getId() : null;

        log.info("MFA State changed from {} to {}", fromState, toState);

        // 메트릭 수집, 감사 로그 등 추가 처리
        recordStateChange(fromState, toState);
    }

    @Override
    public void transition(Transition<MfaState, MfaEvent> transition) {
        if (transition != null && transition.getTrigger() != null) {
            log.debug("Transition triggered by event: {}", transition.getTrigger().getEvent());
        }
    }

    @Override
    public void transitionStarted(Transition<MfaState, MfaEvent> transition) {
        if (transition != null) {
            log.debug("Transition started: {} -> {}",
                    transition.getSource() != null ? transition.getSource().getId() : "null",
                    transition.getTarget() != null ? transition.getTarget().getId() : "null");
        }
    }

    @Override
    public void transitionEnded(Transition<MfaState, MfaEvent> transition) {
        if (transition != null) {
            log.debug("Transition ended: {} -> {}",
                    transition.getSource() != null ? transition.getSource().getId() : "null",
                    transition.getTarget() != null ? transition.getTarget().getId() : "null");
        }
    }

    @Override
    public void stateMachineError(org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine,
                                  Exception exception) {
        log.error("State Machine error occurred: {}", exception.getMessage(), exception);

        // 에러 처리 로직
        handleStateMachineError(stateMachine, exception);
    }

    @Override
    public void onSuccessfulTransition(MfaState from, MfaState to, MfaEvent event) {
        // 성공적인 전이에 대한 추가 처리
        log.info("Successful transition: {} -> {} via event {}", from, to, event);
    }

    @Override
    public void onFailedTransition(MfaState from, MfaEvent event, String reason) {
        // 실패한 전이에 대한 추가 처리
        log.warn("Failed transition from {} with event {}: {}", from, event, reason);
    }

    private void recordStateChange(MfaState from, MfaState to) {
        // 상태 변경 기록 (메트릭, 감사 로그 등)
        // TODO: 실제 메트릭 수집 시스템과 통합
    }

    private void handleStateMachineError(
            org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine,
            Exception exception) {
        // 에러 처리 및 복구 로직
        // TODO: 에러 알림, 복구 시도 등
    }
}