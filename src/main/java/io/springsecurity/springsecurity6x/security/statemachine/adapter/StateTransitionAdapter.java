package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.transition.Transition;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * State 전이 정보를 관리하는 어댑터
 * 전이 가능 여부 판단 및 전이 정보 제공
 */
@Slf4j
@Component
public class StateTransitionAdapter {

    // 상태별 허용된 이벤트 매핑
    private static final Map<MfaState, Map<MfaEvent, MfaState>> TRANSITION_MAP = new HashMap<>();

    static {
        // START_MFA 상태에서의 전이
        Map<MfaEvent, MfaState> startTransitions = new HashMap<>();
        startTransitions.put(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, MfaState.AWAITING_FACTOR_SELECTION);
        startTransitions.put(MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE, MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        startTransitions.put(MfaEvent.MFA_NOT_REQUIRED, MfaState.ALL_FACTORS_COMPLETED);
        TRANSITION_MAP.put(MfaState.START_MFA, startTransitions);

        // AWAITING_FACTOR_SELECTION 상태에서의 전이
        Map<MfaEvent, MfaState> selectionTransitions = new HashMap<>();
        selectionTransitions.put(MfaEvent.FACTOR_SELECTED_OTT, MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        selectionTransitions.put(MfaEvent.FACTOR_SELECTED_PASSKEY, MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        selectionTransitions.put(MfaEvent.USER_ABORTED_MFA, MfaState.MFA_CANCELLED);
        selectionTransitions.put(MfaEvent.SESSION_TIMEOUT, MfaState.MFA_SESSION_EXPIRED);
        TRANSITION_MAP.put(MfaState.AWAITING_FACTOR_SELECTION, selectionTransitions);

        // 더 많은 상태 전이 규칙 추가...
    }

    /**
     * 주어진 상태에서 특정 이벤트가 유효한지 확인
     */
    public boolean isValidTransition(MfaState currentState, MfaEvent event) {
        Map<MfaEvent, MfaState> transitions = TRANSITION_MAP.get(currentState);
        return transitions != null && transitions.containsKey(event);
    }

    /**
     * 전이 후 도달할 상태 반환
     */
    public MfaState getTargetState(MfaState currentState, MfaEvent event) {
        Map<MfaEvent, MfaState> transitions = TRANSITION_MAP.get(currentState);
        return transitions != null ? transitions.get(event) : null;
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

    /**
     * 전이 정보 DTO
     */
    @lombok.Builder
    @lombok.Getter
    public static class TransitionInfo {
        private final MfaState sourceState;
        private final MfaState targetState;
        private final MfaEvent event;
        private final long timestamp = System.currentTimeMillis();
    }
}