package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import org.slf4j.Logger; // 로깅 추가
import org.slf4j.LoggerFactory; // 로깅 추가

import java.util.EnumMap;
import java.util.Map;
import java.util.Collections;

public class StateMachineManager {

    private static final Logger log = LoggerFactory.getLogger(StateMachineManager.class); // 로거 추가

    private final Map<MfaState, Map<MfaEvent, MfaState>> transitions;
    private final AuthenticationFlowConfig flowConfig; // flowConfig를 필드로 유지 (향후 확장성)

    // 생성자에서 flowConfig를 받아 초기화 (향후 flowConfig에 따른 동적 상태머신 구성 가능성)
    public StateMachineManager(AuthenticationFlowConfig flowConfig) {
        this.flowConfig = flowConfig; // flowConfig 저장
        this.transitions = buildTransitionTable(); // 메소드명 변경 및 flowConfig 전달 가능
    }

    // 상태 전이 테이블 구성 (buildTable -> buildTransitionTable로 변경하고, flowConfig 활용 가능)
    private Map<MfaState, Map<MfaEvent, MfaState>> buildTransitionTable() {
        Map<MfaState, Map<MfaEvent, MfaState>> table = new EnumMap<>(MfaState.class);

        // --- 초기 상태 또는 1차 인증 이전 ---
        // (선택적) AWAITING_PRIMARY_AUTHENTICATION 상태 정의
        // table.put(MfaState.AWAITING_PRIMARY_AUTHENTICATION, new EnumMap<>(Map.of(
        // MfaEvent.SUBMIT_CREDENTIAL, MfaState.PRIMARY_AUTHENTICATION_COMPLETED, // 성공 시
        // MfaEvent.VERIFICATION_FAILURE, MfaState.MFA_FAILURE_TERMINAL // 실패 시
        // )));

        // --- 1차 인증 완료 후 (MFA 필요 여부 판단 단계) ---
        table.put(MfaState.PRIMARY_AUTHENTICATION_COMPLETED, new EnumMap<>(Map.of(
                // 시스템이 MFA 필요하다고 판단했고, 자동 시도 Factor가 있는 경우
                MfaEvent.AUTO_ATTEMPT_POSSIBLE, MfaState.AUTO_ATTEMPT_FACTOR_PENDING,
                // 시스템이 MFA 필요하다고 판단했고, 사용자 선택이 필요한 경우 (자동 시도 없거나 실패/스킵)
                MfaEvent.MFA_REQUIRED_SELECT_FACTOR, MfaState.AWAITING_MFA_FACTOR_SELECTION,
                // 시스템이 MFA 필요하다고 판단했고, 단일 Factor로 바로 챌린지 시작
                MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE, MfaState.FACTOR_CHALLENGE_INITIATED,
                // 시스템이 MFA 불필요하다고 판단한 경우
                MfaEvent.MFA_NOT_REQUIRED, MfaState.MFA_VERIFICATION_COMPLETED // 바로 토큰 발급 전 단계로
        )));

        // --- 자동 시도 (예: Passkey Conditional UI) 단계 ---
        table.put(MfaState.AUTO_ATTEMPT_FACTOR_PENDING, new EnumMap<>(Map.of(
                // 사용자가 자동 시도 Factor에 응답 (예: Passkey 선택) 또는 시스템이 챌린지 시작
                MfaEvent.CHALLENGE_INITIATED, MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING,
                // 자동 시도 건너뛰고 수동 선택으로
                MfaEvent.SKIP_AUTO_ATTEMPT, MfaState.AWAITING_MFA_FACTOR_SELECTION,
                // 자동 시도 중 오류 발생 시 수동 선택으로
                MfaEvent.ERROR, MfaState.AWAITING_MFA_FACTOR_SELECTION
        )));

        table.put(MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                // 자동 시도 Factor 검증 성공
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED, // 모든 MFA 완료
                // 자동 시도 Factor 검증 실패
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION // 다른 Factor 선택으로
        )));

        // --- 사용자가 MFA Factor를 선택하는 단계 ---
        table.put(MfaState.AWAITING_MFA_FACTOR_SELECTION, new EnumMap<>(Map.of(
                // 사용자가 특정 Factor를 선택함
                MfaEvent.FACTOR_SELECTED, MfaState.FACTOR_CHALLENGE_INITIATED
        )));

        // --- 선택된 Factor에 대한 챌린지 시작/진행 단계 ---
        table.put(MfaState.FACTOR_CHALLENGE_INITIATED, new EnumMap<>(Map.of(
                // 사용자가 Factor에 대한 자격증명(코드, 서명 등)을 제출
                MfaEvent.SUBMIT_CREDENTIAL, MfaState.FACTOR_VERIFICATION_PENDING,
                // 챌린지 생성/전달 중 오류 발생
                MfaEvent.CHALLENGE_DELIVERY_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION, // 오류 시 다시 선택
                MfaEvent.ERROR, MfaState.AWAITING_MFA_FACTOR_SELECTION // 일반 오류 시 다시 선택
        )));

        // --- Factor 검증 진행 단계 ---
        table.put(MfaState.FACTOR_VERIFICATION_PENDING, new EnumMap<>(Map.of(
                // 현재 Factor 검증 성공
                MfaEvent.VERIFICATION_SUCCESS, MfaState.MFA_VERIFICATION_COMPLETED, // 다음 Factor 또는 모든 MFA 완료
                // 현재 Factor 검증 실패
                MfaEvent.VERIFICATION_FAILURE, MfaState.AWAITING_MFA_FACTOR_SELECTION, // 실패 시 다시 선택 (재시도 정책은 MfaStateHandler에서)
                // 검증 시간 초과
                MfaEvent.TIMEOUT, MfaState.MFA_SESSION_INVALIDATED
        )));

        // --- 모든 MFA Factor 검증 완료, 토큰 발급 대기 ---
        table.put(MfaState.MFA_VERIFICATION_COMPLETED, new EnumMap<>(Map.of(
                // 최종 토큰 발급 요청
                MfaEvent.ISSUE_TOKEN, MfaState.MFA_FULLY_COMPLETED
        )));

        // --- 최종(터미널) 상태들 ---
        table.put(MfaState.MFA_FULLY_COMPLETED, Collections.emptyMap()); // 더 이상 전이 없음
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