package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.transition.Transition;
import org.springframework.stereotype.Component;

/**
 * State 전이 정보를 관리하는 어댑터
 * StateMachineFactory 에서 실시간으로 전이 정보 조회
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateTransitionAdapter {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;

    /**
     * 주어진 상태에서 특정 이벤트가 유효한지 확인
     */
    public boolean isValidTransition(MfaState currentState, MfaEvent event) {
        // StateMachine 에서 직접 전이 가능 여부 확인
        return stateMachineFactory.getStateMachine()
                .getTransitions()
                .stream()
                .anyMatch(t -> t.getSource().getId().equals(currentState)
                        && t.getTrigger().getEvent().equals(event));
    }

    /**
     * State Machine 전이 컨텍스트에서 정보 추출
     */
    public TransitionInfo extractTransitionInfo(Transition<MfaState, MfaEvent> transition) {
        return TransitionInfo.builder()
                .sourceState(transition.getSource().getId())
                .targetState(transition.getTarget().getId())
                .event(transition.getTrigger().getEvent())
                .build();
    }

    @lombok.Builder
    @lombok.Getter
    public static class TransitionInfo {
        private final MfaState sourceState;
        private final MfaState targetState;
        private final MfaEvent event;
        private final long timestamp = System.currentTimeMillis();
    }
}