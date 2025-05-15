package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException; // 가정된 경로

import java.util.EnumMap;
import java.util.Map;
import java.util.Collections;

public class StateMachineManager {

    private final Map<MfaState, Map<MfaEvent, MfaState>> transitions;

    @SuppressWarnings("unused") // flowConfig는 향후 확장성을 위해 남겨둘 수 있음
    public StateMachineManager(AuthenticationFlowConfig flowConfig) {
        this.transitions = buildTable();
    }

    private Map<MfaState, Map<MfaEvent, MfaState>> buildTable() {
        Map<MfaState, Map<MfaEvent, MfaState>> table = new EnumMap<>(MfaState.class);

        table.put(MfaState.PRIMARY_AUTHENTICATION_COMPLETED, new EnumMap<>(Map.of(
                MfaEvent.REQUEST_CHALLENGE, MfaState.AUTO_ATTEMPT_FACTOR_PENDING,
                MfaEvent.SELECT_MFA_METHOD, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        table.put(MfaState.AUTO_ATTEMPT_FACTOR_PENDING, new EnumMap<>(Map.of(
                MfaEvent.CHALLENGE_INITIATED, MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING,
                MfaEvent.SKIP_AUTO_ATTEMPT, MfaState.AWAITING_MFA_FACTOR_SELECTION,
                MfaEvent.SELECT_MFA_METHOD, MfaState.AWAITING_MFA_FACTOR_SELECTION,
                MfaEvent.ERROR, MfaState.AWAITING_MFA_FACTOR_SELECTION // 챌린지 생성/시작 자체의 오류
        )));

        table.put(MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED,
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        table.put(MfaState.AWAITING_MFA_FACTOR_SELECTION, new EnumMap<>(Map.of(
                MfaEvent.FACTOR_SELECTED, MfaState.FACTOR_CHALLENGE_INITIATED
        )));

        table.put(MfaState.FACTOR_CHALLENGE_INITIATED, new EnumMap<>(Map.of(
                // 챌린지 성공적 제시 후 사용자가 자격 증명 제출 시
                MfaEvent.SUBMIT_CREDENTIAL, MfaState.FACTOR_VERIFICATION_PENDING,
                // 챌린지 생성/요청 단계에서 오류 발생 시 (예: 외부 API 호출 실패)
                MfaEvent.ERROR, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        table.put(MfaState.FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED,
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION, // 실패 시 다시 선택 (재시도 로직은 외부에서)
                MfaEvent.TIMEOUT, MfaState.MFA_SESSION_INVALIDATED // 검증 단계 타임아웃
        )));

        table.put(MfaState.MFA_VERIFICATION_COMPLETED, new EnumMap<>(Map.of(
                MfaEvent.ISSUE_TOKEN, MfaState.MFA_FULLY_COMPLETED
        )));

        table.put(MfaState.MFA_FULLY_COMPLETED, Collections.emptyMap());
        table.put(MfaState.MFA_FAILURE_TERMINAL, Collections.emptyMap());
        table.put(MfaState.MFA_SESSION_INVALIDATED, Collections.emptyMap());
        table.put(MfaState.MFA_SYSTEM_ERROR, Collections.emptyMap());

        return Collections.unmodifiableMap(table);
    }

    public MfaState nextState(MfaState currentState, MfaEvent event) {
        Map<MfaEvent, MfaState> possibleTransitions = transitions.get(currentState);
        if (possibleTransitions == null || !possibleTransitions.containsKey(event)) {
            throw new InvalidTransitionException(currentState, event);
        }
        return possibleTransitions.get(event);
    }
}