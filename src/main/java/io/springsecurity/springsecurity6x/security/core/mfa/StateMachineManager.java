package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent; // 올바른 경로로 가정
import io.springsecurity.springsecurity6x.security.enums.MfaState; // 올바른 경로로 가정
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException; // 올바른 경로로 가정

import java.util.EnumMap;
import java.util.Map;
import java.util.Collections;

public class StateMachineManager {

    private final Map<MfaState, Map<MfaEvent, MfaState>> transitions;

    /**
     * 생성자.
     * @param flowConfig 현재 MFA 흐름에 대한 설정을 담고 있는 객체.
     * (주의: 이 리팩토링에서는 flowConfig를 직접 사용하여 복잡한 상태 전이를 만들지 않고,
     * 일반화된 MFA 상태 전이 규칙을 사용합니다.)
     */
    public StateMachineManager(AuthenticationFlowConfig flowConfig) {
        // flowConfig는 로깅이나 특정 플래그 기반의 조건부 로직에 사용될 수 있으나,
        // 핵심 상태 전이 로직은 아래 buildTable()에서 일반화된 형태로 정의됩니다.
        // 현재는 flowConfig 파라미터를 사용하지 않으므로, 제거하거나 @SuppressWarnings("unused") 추가 가능
        this.transitions = buildTable();
    }

    /**
     * 새로운 MFA 흐름에 따른 일반적인 상태 전이 테이블을 정의합니다.
     * MfaEvent.CHALLENGE_FAILURE 이벤트는 현재 MfaEvent enum에 없다고 가정하고,
     * 해당 상황에서는 AWAITING_MFA_FACTOR_SELECTION으로 가는 다른 적절한 이벤트 (예: ERROR 또는 특정 실패 이벤트)를
     * 사용하거나, 해당 전이 로직을 MfaFailureHandler에서 처리하도록 합니다.
     * 여기서는 ERROR 이벤트를 사용하여 실패 시 선택 화면으로 돌아가도록 단순화합니다.
     */
    private Map<MfaState, Map<MfaEvent, MfaState>> buildTable() {
        Map<MfaState, Map<MfaEvent, MfaState>> table = new EnumMap<>(MfaState.class);

        // 1차 인증 완료 후: 자동 시도 Factor가 있는지 확인하거나, Factor 선택 화면으로 이동 준비
        table.put(MfaState.PRIMARY_AUTHENTICATION_COMPLETED, new EnumMap<>(Map.of(
                MfaEvent.REQUEST_CHALLENGE, MfaState.AUTO_ATTEMPT_FACTOR_PENDING,
                MfaEvent.SELECT_MFA_METHOD, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        // 자동 시도 Factor 처리 (예: Passkey Conditional UI)
        table.put(MfaState.AUTO_ATTEMPT_FACTOR_PENDING, new EnumMap<>(Map.of(
                MfaEvent.CHALLENGE_INITIATED, MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING,
                MfaEvent.SKIP_AUTO_ATTEMPT, MfaState.AWAITING_MFA_FACTOR_SELECTION,
                MfaEvent.SELECT_MFA_METHOD, MfaState.AWAITING_MFA_FACTOR_SELECTION,
                MfaEvent.ERROR, MfaState.AWAITING_MFA_FACTOR_SELECTION // 자동 시도 자체의 실패(챌린지 생성 실패 등)
        )));

        // 자동 시도 Factor 검증 중
        table.put(MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED,
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        // 사용자가 MFA Factor 선택 대기
        table.put(MfaState.AWAITING_MFA_FACTOR_SELECTION, new EnumMap<>(Map.of(
                MfaEvent.FACTOR_SELECTED, MfaState.FACTOR_CHALLENGE_INITIATED
        )));

        // 특정 Factor 챌린지 시작됨
        table.put(MfaState.FACTOR_CHALLENGE_INITIATED, new EnumMap<>(Map.of(
                // 챌린지가 성공적으로 사용자에게 제시/발송된 후 사용자가 입력을 제출하는 이벤트로 통합.
                // 또는 MfaEvent.CHALLENGE_PREPARED (가칭) 등으로 상태 변경 후 VERIFICATION_PENDING으로.
                MfaEvent.SUBMIT_CREDENTIAL, MfaState.FACTOR_VERIFICATION_PENDING,
                // 챌린지 생성/요청 단계에서 실패하여 다시 Factor 선택으로.
                // MfaEvent.CHALLENGE_FAILURE 대신 ERROR 이벤트를 사용하거나,
                // 이 부분은 MfaFailureHandler 에서 처리하고 상태 변경을 직접 유도할 수 있음.
                // 여기서는 상태 기계가 모든 전이를 알아야 한다고 가정하고 ERROR 사용.
                MfaEvent.ERROR, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        // 특정 Factor 검증 대기
        table.put(MfaState.FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED,
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        // 모든 필요한 MFA 검증 완료
        table.put(MfaState.MFA_VERIFICATION_COMPLETED, new EnumMap<>(Map.of(
                MfaEvent.ISSUE_TOKEN, MfaState.MFA_FULLY_COMPLETED
        )));

        // 최종 상태들 - 더 이상 상태 전이 없음
        table.put(MfaState.MFA_FULLY_COMPLETED, Collections.emptyMap());
        table.put(MfaState.MFA_FAILURE_TERMINAL, Collections.emptyMap());
        table.put(MfaState.MFA_SESSION_INVALIDATED, Collections.emptyMap());
        table.put(MfaState.MFA_SYSTEM_ERROR, Collections.emptyMap());

        return Collections.unmodifiableMap(table);
    }

    /**
     * 현재 상태와 발생한 이벤트를 기반으로 다음 상태를 반환합니다.
     *
     * @param currentState 현재 MfaState
     * @param event 발생한 MfaEvent
     * @return 다음 MfaState
     * @throws InvalidTransitionException 정의되지 않은 상태 전이 시 발생
     */
    public MfaState nextState(MfaState currentState, MfaEvent event) {
        Map<MfaEvent, MfaState> possibleTransitions = transitions.get(currentState);
        if (possibleTransitions == null || !possibleTransitions.containsKey(event)) {
            // 좀 더 구체적인 예외 메시지를 위해 FactorContext 에서 현재 Factor 정보를 가져와 포함할 수도 있음
            throw new InvalidTransitionException(currentState, event);
        }
        return possibleTransitions.get(event);
    }
}