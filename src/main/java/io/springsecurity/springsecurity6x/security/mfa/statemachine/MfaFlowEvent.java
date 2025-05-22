package io.springsecurity.springsecurity6x.security.mfa.statemachine;

/**
 * MFA 인증 흐름의 상태 전이를 유발하는 이벤트를 정의합니다.
 * 스프링 상태 머신의 Event로 사용됩니다.
 */
public enum MfaFlowEvent {
    // 초기화 및 1차 인증 관련 이벤트
    PRIMARY_AUTH_COMPLETED,     // 1차 인증 성공 이벤트

    // 2차 요소 선택 관련 이벤트
    FACTOR_SELECT_REQUESTED,    // 사용자가 2차 인증 요소 선택 화면 요청
    FACTOR_SELECTED_OTT,        // 사용자가 OTT를 2차 인증 요소로 선택
    FACTOR_SELECTED_PASSKEY,    // 사용자가 Passkey를 2차 인증 요소로 선택
    // TODO: 다른 MFA 요소 선택 이벤트 추가 가능

    // OTT 관련 이벤트
    OTT_CHALLENGE_REQUESTED,    // OTT 코드 발송 요청 (사용자 또는 시스템)
    OTT_CHALLENGE_ISSUED,       // OTT 코드 발송 성공
    OTT_SUBMITTED,              // 사용자가 OTT 코드 제출
    OTT_VERIFIED,               // OTT 코드 검증 성공
    OTT_VERIFICATION_FAILED,    // OTT 코드 검증 실패

    // Passkey 관련 이벤트
    PASSKEY_CHALLENGE_REQUESTED, // Passkey Assertion Options 요청
    PASSKEY_CHALLENGE_ISSUED,    // Passkey Assertion Options 생성/반환 성공
    PASSKEY_ASSERTION_SUBMITTED, // 사용자가 Passkey Assertion 제출
    PASSKEY_VERIFIED,            // Passkey 검증 성공
    PASSKEY_VERIFICATION_FAILED, // Passkey 검증 실패
    // TODO: 다른 MFA 요소 처리 이벤트 추가 가능

    // 일반적인 성공/실패/재시도/취소 이벤트
    FACTOR_VERIFICATION_SUCCESS, // 현재 진행 중인 팩터 검증 성공 (공통 이벤트로 사용 가능)
    FACTOR_VERIFICATION_FAILURE, // 현재 진행 중인 팩터 검증 실패 (공통 이벤트로 사용 가능)
    RETRY_REQUESTED,            // 사용자 또는 시스템의 재시도 요청
    CANCEL_MFA_REQUESTED,       // 사용자의 MFA 흐름 취소 요청
    NO_FACTORS_REGISTERED,      // 사용자에게 등록된 MFA 요소가 없음
    ALL_REQUIRED_FACTORS_COMPLETED, // 모든 필수 MFA 요소 완료
    POLICY_ALLOWS_BYPASS,       // MFA 정책에 따라 현재 단계/흐름 생략 허용

    // 시간 초과 이벤트 (선택적)
    TIMEOUT
}