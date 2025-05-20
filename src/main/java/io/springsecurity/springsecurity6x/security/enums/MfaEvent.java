package io.springsecurity.springsecurity6x.security.enums;

public enum MfaEvent {
    // --- 기존 이벤트 (일부는 의미가 더 명확한 새 이벤트로 대체될 수 있음) ---
    /** 사용자가 (1차 또는 2차) 자격 증명을 제출 (예: 비밀번호, OTT 코드, Passkey 응답 등) */
    SUBMIT_CREDENTIAL,
    /** 모든 인증 완료 후 토큰 발급 요청 */
    ISSUE_TOKEN,
    /** 복구 흐름 시작 요청 (별도의 Factor로 처리될 수도 있음) */
    RECOVER, // 이 이벤트는 RECOVERY_CODE Factor 선택 시 FACTOR_SELECTED로 대체될 수 있음
    /** 인증 유효 시간 초과 */
    TIMEOUT,
    /** 일반 또는 특정 단계에서의 오류 발생 */
    ERROR,

    // --- 1차 인증 관련 이벤트 ---
    /** 1차 인증(예: ID/PW) 성공 */
    PRIMARY_AUTH_SUCCESS, // StateMachineManager에서 이 이벤트를 직접 사용하진 않지만, 외부에서 상태 변경 트리거로 사용 가능
    /** 1차 인증 실패 */
    PRIMARY_AUTH_FAILURE, // MFA_FAILURE_TERMINAL로 가는 트리거

    // --- MFA 필요 여부 판단 및 자동 시도 관련 이벤트 (PRIMARY_AUTHENTICATION_COMPLETED 상태에서 발생) ---
    /** MFA가 필요하며, 자동 시도 가능한 Factor가 있는 경우 (예: Passkey Conditional UI) */
    AUTO_ATTEMPT_POSSIBLE,
    /** MFA가 필요하며, 사용자가 직접 Factor를 선택해야 하는 경우 */
    MFA_REQUIRED_SELECT_FACTOR,
    /** MFA가 필요하며, 시스템 정책에 따라 특정 Factor로 바로 챌린지를 시작해야 하는 경우 */
    MFA_REQUIRED_INITIATE_CHALLENGE,
    /** MFA가 필요하지 않은 경우 (바로 토큰 발급 단계로) */
    MFA_NOT_REQUIRED,

    // --- 자동 시도(AUTO_ATTEMPT_FACTOR_PENDING) 관련 이벤트 ---
    /** 자동 시도 Factor에 대한 챌린지가 성공적으로 시작/요청됨 (예: Passkey get() 호출 또는 Conditional UI 표시) */
    CHALLENGE_INITIATED, // AUTO_ATTEMPT_FACTOR_PENDING -> AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING

    // 또는 FACTOR_SELECTED 이후 FACTOR_CHALLENGE_INITIATED -> FACTOR_VERIFICATION_PENDING
    /** 자동 시도 Factor를 건너뛰고 수동으로 다른 Factor를 선택하기로 함 */
    SKIP_AUTO_ATTEMPT,

    // --- 사용자 Factor 선택(AWAITING_MFA_FACTOR_SELECTION) 관련 이벤트 ---
    /** 사용자가 MFA Factor를 선택함 (선택된 Factor 정보는 FactorContext에 저장됨) */
    FACTOR_SELECTED,

    // --- Factor 챌린지/검증 관련 공통 이벤트 ---
    // CHALLENGE_INITIATED는 위에서 자동 시도용으로도 사용되지만, 수동 Factor 선택 후에도 사용 가능
    // MfaEvent.REQUEST_CHALLENGE는 CHALLENGE_INITIATED로 통합하거나, 더 구체적인 의미로 사용 가능
    // 기존 REQUEST_CHALLENGE: 특정 Factor에 대한 챌린지 생성/요청 (예: Passkey options 요청, OTT 코드 생성 요청)
    // 혼동을 피하기 위해 CHALLENGE_INITIATED를 주로 사용하고, 필요시 REQUEST_CHALLENGE는 특정 API 호출 지점에서 사용
    REQUEST_CHALLENGE, // (선택적 유지 또는 CHALLENGE_INITIATED와 통합 고려)

    /** Factor 챌린지(예: OTT 코드)가 사용자에게 성공적으로 전달됨 */
    CHALLENGE_DELIVERED,
    /** Factor 챌린지 전달 실패 */
    CHALLENGE_DELIVERY_FAILURE,
    /** 특정 Factor 검증 성공 */
    VERIFICATION_SUCCESS,
    /** 특정 Factor 검증 실패 */
    VERIFICATION_FAILURE;

    // SELECT_MFA_METHOD (AUTO_ATTEMPT_FACTOR_PENDING 등에서) 다른 MFA 방법 선택 화면으로 가기 요청
    // SKIP_AUTO_ATTEMPT 와 유사하거나 통합될 수 있음. 여기서는 SKIP_AUTO_ATTEMPT를 주로 사용.
}

