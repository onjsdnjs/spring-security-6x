package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

public class StateMachineManager {

    private static final Logger log = LoggerFactory.getLogger(StateMachineManager.class);

    private final Map<MfaState, Map<MfaEvent, MfaState>> transitions;
    // private final AuthenticationFlowConfig flowConfig; // 현재 코드에서는 직접 사용되지 않음

    public StateMachineManager(/* AuthenticationFlowConfig flowConfig */) { // flowConfig 제거 또는 주석 처리
        // this.flowConfig = flowConfig;
        this.transitions = buildTransitionTable();
    }

    private Map<MfaState, Map<MfaEvent, MfaState>> buildTransitionTable() {
        Map<MfaState, Map<MfaEvent, MfaState>> table = new EnumMap<>(MfaState.class);

        // 1차 인증 완료 후
        table.put(MfaState.PRIMARY_AUTHENTICATION_COMPLETED, new EnumMap<>(Map.of(
                MfaEvent.AUTO_ATTEMPT_POSSIBLE, MfaState.AUTO_ATTEMPT_FACTOR_PENDING,
                MfaEvent.MFA_REQUIRED_SELECT_FACTOR, MfaState.AWAITING_FACTOR_SELECTION, // 이전 코드와 일치 AWAITING_MFA_FACTOR_SELECTION
                MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE, MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION, // FactorSelectionStateHandler의 반환값과 일치 확인 필요
                MfaEvent.MFA_NOT_REQUIRED, MfaState.MFA_VERIFICATION_COMPLETED
        )));

        // 자동 시도 (예: Passkey Conditional UI)
        table.put(MfaState.AUTO_ATTEMPT_FACTOR_PENDING, new EnumMap<>(Map.of(
                MfaEvent.CHALLENGE_INITIATED, MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING,
                MfaEvent.SKIP_AUTO_ATTEMPT, MfaState.AWAITING_FACTOR_SELECTION, // AWAITING_MFA_FACTOR_SELECTION
                MfaEvent.ERROR, MfaState.AWAITING_FACTOR_SELECTION // AWAITING_MFA_FACTOR_SELECTION
        )));

        table.put(MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED,
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_FACTOR_SELECTION // AWAITING_MFA_FACTOR_SELECTION
        )));

        // 사용자 MFA Factor 선택
        // AWAITING_FACTOR_SELECTION (또는 AWAITING_MFA_FACTOR_SELECTION)
        table.put(MfaState.AWAITING_FACTOR_SELECTION, new EnumMap<>(Map.of(
                MfaEvent.FACTOR_SELECTED, MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION
        )));

        // 선택된 Factor에 대한 챌린지 시작/요청 대기
        // (FactorSelectionStateHandler에서 FACTOR_SELECTED 이후 이 상태로 전이됨)
        table.put(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION, new EnumMap<>(Map.of(
                // 이 상태에서는 실제 챌린지를 "생성/요청"하는 액션이 발생하고,
                // 그 결과에 따라 CHALLENGE_INITIATED 또는 CHALLENGE_DELIVERY_FAILURE, ERROR 이벤트가 발생하여 다음 상태로 전이해야 함.
                // 예를 들어, ChallengeRouter 에서 챌린지 생성 후 CHALLENGE_INITIATED 이벤트를 발생시켜야 함.
                // 또는 이 상태를 처리하는 별도 핸들러가 필요할 수 있음.
                // 지금 상태로는 이 상태에서 머무르게 됨.
                // 만약 이 상태에서 바로 사용자가 credential을 제출한다면, 이벤트가 SUBMIT_CREDENTIAL, 다음 상태가 FACTOR_VERIFICATION_PENDING 이 될 수 있으나,
                // 상태 이름(AWAITING_FACTOR_CHALLENGE_INITIATION)과는 맞지 않음.
                // 우선, 챌린지가 성공적으로 "시작되었다"는 가정하에 다음 상태로 넘어가는 것을 정의.
                // 이는 외부(예: MfaApiController 또는 ChallengeRouter)에서 해당 이벤트를 발생시켜야 함.
                MfaEvent.CHALLENGE_INITIATED, MfaState.FACTOR_CHALLENGE_INITIATED, // 챌린지 UI 로드 또는 실제 챌린지 발송 완료
                MfaEvent.CHALLENGE_DELIVERY_FAILURE, MfaState.AWAITING_FACTOR_SELECTION, // AWAITING_MFA_FACTOR_SELECTION
                MfaEvent.ERROR, MfaState.AWAITING_FACTOR_SELECTION // AWAITING_MFA_FACTOR_SELECTION
        )));


        // Factor 챌린지 진행 (사용자 응답 대기)
        table.put(MfaState.FACTOR_CHALLENGE_INITIATED, new EnumMap<>(Map.of(
                MfaEvent.SUBMIT_CREDENTIAL, MfaState.FACTOR_VERIFICATION_PENDING,
                MfaEvent.CHALLENGE_DELIVERY_FAILURE, MfaState.AWAITING_FACTOR_SELECTION, // AWAITING_MFA_FACTOR_SELECTION
                MfaEvent.ERROR, MfaState.AWAITING_FACTOR_SELECTION, // AWAITING_MFA_FACTOR_SELECTION
                MfaEvent.TIMEOUT, MfaState.MFA_SESSION_INVALIDATED // 각 핸들러에서도 TIMEOUT 처리 가능
        )));

        // Factor 검증 진행
        table.put(MfaState.FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED, // 실제로는 MfaPolicyProvider.determineNextFactor 에 따라 다음 Factor 또는 완료
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_FACTOR_SELECTION, // AWAITING_MFA_FACTOR_SELECTION (재시도 정책은 MfaFailureHandler 또는 MfaPolicyProvider)
                MfaEvent.TIMEOUT, MfaState.MFA_SESSION_INVALIDATED
        )));

        // 모든 MFA Factor 검증 완료
        table.put(MfaState.MFA_VERIFICATION_COMPLETED, new EnumMap<>(Map.of(
                MfaEvent.ISSUE_TOKEN, MfaState.MFA_FULLY_COMPLETED
        )));

        // 최종(터미널) 상태들
        table.put(MfaState.MFA_FULLY_COMPLETED, Collections.emptyMap());
        table.put(MfaState.MFA_FAILURE_TERMINAL, Collections.emptyMap());
        table.put(MfaState.MFA_SESSION_INVALIDATED, Collections.emptyMap());
        table.put(MfaState.MFA_SYSTEM_ERROR, Collections.emptyMap());

        return Collections.unmodifiableMap(table);
    }

    public MfaState nextState(MfaState currentState, MfaEvent event) {
        log.debug("Attempting transition from state: {} with event: {}", currentState, event);
        Map<MfaEvent, MfaState> possibleTransitions = transitions.get(currentState);

        if (possibleTransitions == null) {
            log.error("No transitions defined for current state: {}", currentState);
            throw new InvalidTransitionException(currentState, event);
        }

        if (!possibleTransitions.containsKey(event)) {
            log.error("Invalid event: {} for current state: {}. Possible transitions: {}", event, currentState, possibleTransitions.keySet());
            throw new InvalidTransitionException(currentState, event);
        }

        MfaState nextState = possibleTransitions.get(event);
        log.info("Transitioning from {} to {} on event {}", currentState, nextState, event);
        return nextState;
    }
}