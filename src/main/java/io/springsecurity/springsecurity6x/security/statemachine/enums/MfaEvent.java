package io.springsecurity.springsecurity6x.security.statemachine.enums;

public enum MfaEvent {

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
    TIMEOUT,

    // --- 1차 인증 및 초기화 ---

    // --- MFA 정책 결과 및 팩터 선택 ---
    MFA_POLICY_EVALUATED_SELECT_FACTOR, // 정책 평가 결과: MFA 필요, 사용자 선택 (기존 MFA_REQUIRED_SELECT_FACTOR 와 유사)
    MFA_POLICY_EVALUATED_INITIATE_FACTOR, // 정책 평가 결과: MFA 필요, 특정 팩터 즉시 시작 (기존 MFA_REQUIRED_INITIATE_CHALLENGE 와 유사, payload로 팩터 타입 전달)
    MFA_POLICY_ALLOWS_BYPASS,          // 정책 평가 결과: MFA 건너뛰기 허용 (기존 MFA_NOT_REQUIRED 와 유사)

    // FACTOR_SELECT_REQUESTED는 UI 요청이므로 상태머신 이벤트보다는 컨트롤러 레벨에서 처리 후 UI 반환.

    // --- 챌린지 처리 ---
    INITIATE_CHALLENGE,         // 특정 팩터에 대한 챌린지 시작 요청 (내부 이벤트 또는 FACTOR_SELECTED의 결과)
    CHALLENGE_ISSUED_SUCCESSFULLY, // OTP 발송 성공, Passkey 옵션 생성 성공 등 (기존 OTT_CHALLENGE_ISSUED, PASSKEY_CHALLENGE_ISSUED 와 유사)
    CHALLENGE_ISSUANCE_FAILED,   // 챌린지 발급 실패 (기존 CHALLENGE_INITIATION_FAILED 와 유사)

    // --- 사용자 응답 제출 ---
    SUBMIT_OTT_CODE,            // 사용자가 OTT 코드 제출 (기존 OTT_SUBMITTED 와 유사)
    SUBMIT_PASSKEY_ASSERTION,   // 사용자가 Passkey Assertion 제출 (기존 PASSKEY_ASSERTION_SUBMITTED 와 유사)
    // SUBMIT_FACTOR_CREDENTIAL 은 너무 일반적이므로 각 팩터 타입별로 구체화된 이벤트 사용

    // --- 검증 결과 ---
    FACTOR_VERIFIED_SUCCESS,    // 현재 팩터 검증 성공 (기존 OTT_VERIFIED, PASSKEY_VERIFIED 와 유사, payload로 어떤 팩터인지 전달)
    FACTOR_VERIFICATION_FAILED, // 현재 팩터 검증 실패 (기존 OTT_VERIFICATION_FAILED, PASSKEY_VERIFICATION_FAILED 와 유사)

    // --- 사용자 취소 및 예외 ---
    USER_ABORTED_MFA,             // 사용자가 MFA 흐름 중단
    RETRY_LIMIT_EXCEEDED,         // 재시도 횟수 초과
    SESSION_TIMEOUT,              // MFA 세션 타임아웃
    SYSTEM_ERROR,                // 예측 불가능한 시스템 오류

    // --- 1차 인증 결과 관련 이벤트 (주로 PrimaryAuthenticationSuccessHandler에서 FactorContext 상태 변경에 사용) ---
    PRIMARY_AUTH_SUCCESS, // 1차 인증 성공 (MFA 필요 여부는 FactorContext.mfaRequiredAsPerPolicy로 판단)
    PRIMARY_AUTH_FAILURE, // 1차 인증 실패 (MFA_FAILED_TERMINAL 상태로 직결될 수 있음)

    // --- MFA 정책 평가 결과 (1차 인증 성공 핸들러에서 FactorContext 상태 설정에 사용) ---
    MFA_NOT_REQUIRED,             // MFA 불필요 (ALL_FACTORS_COMPLETED 상태로)
    MFA_REQUIRED_SELECT_FACTOR,   // MFA 필요, 사용자 선택 대기 (AWAITING_FACTOR_SELECTION 상태로)
    MFA_REQUIRED_INITIATE_CHALLENGE, // MFA 필요, 특정 Factor로 챌린지 즉시 시작 (AWAITING_FACTOR_CHALLENGE_INITIATION 상태로)

    // --- 사용자의 명시적 액션 관련 이벤트 (주로 MfaApiController에서 발생시켜 Request Attribute로 전달) ---
    FACTOR_SELECTED,              // 사용자가 2차 인증 수단 선택

    // --- 시스템 또는 Factor 내부 처리 이벤트 ---
    CHALLENGE_INITIATED_SUCCESSFULLY, // Factor 챌린지(예: OTT 발송, Passkey 옵션 생성) 성공적 시작/제시
    CHALLENGE_INITIATION_FAILED,    // Factor 챌린지 시작/제시 실패 (CHALLENGE_DELIVERY_FAILURE와 통합 가능)

    SUBMIT_FACTOR_CREDENTIAL,     // 사용자가 2차 인증 정보(OTP, Passkey 응답 등) 제출

   /* FACTOR_VERIFICATION_SUCCESS,  // 특정 2차 인증 Factor 검증 성공
    FACTOR_VERIFICATION_FAILURE,  // 특정 2차 인증 Factor 검증 실패*/

    ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, // 모든 필수 Factor 검증 완료, 토큰 발급 단계로 (기존 ISSUE_TOKEN 역할)

    // --- 예외 및 특수 상황 이벤트 ---
    CHALLENGE_DELIVERY_FAILURE,   // (CHALLENGE_INITIATION_FAILED와 통합 가능) Factor 챌린지 전달 실패 (예: 이메일 발송 실패)
    SKIP_AUTO_ATTEMPT,            // (AUTO_ATTEMPT 기능 사용 시) 자동 시도 건너뛰기
    REQUEST_RECOVERY,

    MFA_CONFIGURATION_REQUIRED,
    PRIMARY_FACTOR_COMPLETED,
    CHALLENGE_TIMEOUT;             // (RECOVER와 유사) 복구 흐름 요청

    // --- 기존 이벤트 중 재검토 또는 대체된 이벤트 ---
    // SUBMIT_CREDENTIAL: FACTOR_VERIFICATION_PENDING 상태를 유발하는 더 일반적인 이벤트로 사용.
    // ISSUE_TOKEN: ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN 으로 대체.
    // RECOVER: REQUEST_RECOVERY 또는 AuthType.RECOVERY_CODE 선택 시 FACTOR_SELECTED 로 처리.
    // TIMEOUT: SESSION_TIMEOUT 으로 명확화.
    // ERROR: SYSTEM_ERROR 또는 구체적인 실패 이벤트로 대체.
    // AUTO_ATTEMPT_POSSIBLE: PRIMARY_AUTH_SUCCESS 후 MfaPolicyProvider가 판단하여 FactorContext에 preferredAutoAttemptFactor 설정.
    // CHALLENGE_INITIATED: CHALLENGE_INITIATED_SUCCESSFULLY 로 명확화.
    // REQUEST_CHALLENGE: 구체적인 Factor의 챌린지 시작 로직(예: MfaContinuationFilter)에서 CHALLENGE_INITIATED_SUCCESSFULLY/FAILED 이벤트 발생으로 대체.
    // CHALLENGE_DELIVERED: CHALLENGE_INITIATED_SUCCESSFULLY 로 통합.
}
