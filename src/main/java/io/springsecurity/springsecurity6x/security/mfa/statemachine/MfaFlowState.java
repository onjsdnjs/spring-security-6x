package io.springsecurity.springsecurity6x.security.mfa.statemachine;

import static io.springsecurity.springsecurity6x.security.enums.MfaState.*;

/**
 * MFA 인증 흐름의 상태를 정의합니다.
 * 스프링 상태 머신의 State로 사용됩니다.
 */
public enum MfaFlowState {
    // 초기 상태
    START_MFA,                // MFA 흐름 시작 (1차 인증 성공 직후)

    // 1차 인증 관련 상태 (필요시 세분화)
    PRIMARY_AUTHENTICATION_SUCCESSFUL, // 1차 인증 성공, 2차 요소 결정 필요

    // 2차 요소 선택 및 처리 상태
    AWAITING_FACTOR_SELECTION,    // 사용자에게 2차 인증 요소 선택 대기
    FACTOR_SELECTED,              // 사용자가 2차 인증 요소 선택 완료

    AWAITING_OTT_VERIFICATION,    // OTT 코드 입력 대기 (코드 발송 후)
    OTT_VERIFICATION_SUCCESSFUL,  // OTT 코드 검증 성공
    AWAITING_PASSKEY_VERIFICATION,// Passkey 검증 대기 (Assertion Options 생성 후)
    PASSKEY_VERIFICATION_SUCCESSFUL, // Passkey 검증 성공
    // TODO: 다른 MFA 요소(예: Recovery Code) 상태 추가 가능

    // MFA 흐름 완료 상태
    MFA_SUCCESSFUL,             // 모든 필수 MFA 요소 검증 완료 (최종 인증 성공)
    MFA_COMPLETED_PARTIALLY,    // 일부 요소만 완료되었으나, 정책에 따라 다음 단계 진행 또는 추가 요소 필요 (예: 계층적 상태에서 사용)

    // MFA 흐름 실패/종료 상태
    MFA_FAILURE,                // MFA 인증 실패 (특정 요소 실패 또는 전역 실패)
    MFA_CANCELLED,              // 사용자에 의한 MFA 흐름 취소
    MFA_CONFIGURATION_REQUIRED, // 사용자에게 MFA 설정이 필요함 (등록된 요소 없음)
    MFA_RETRY_LIMIT_EXCEEDED,   // 재시도 횟수 초과

    // 종료 상태
    END_MFA                     // MFA 흐름 완전 종료

}