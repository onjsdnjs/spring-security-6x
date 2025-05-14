package io.springsecurity.springsecurity6x.security.enums;

/**
 * MFA 상태 전이를 유발하는 이벤트 열거형
 * 인증 흐름 내에서 사용자의 입력 또는 시스템 상황에 따라 발생하며,
 * 현재 상태와 함께 다음 상태로의 전이를 결정한다.
 */
public enum MfaEvent {

    /** 인증 단계에 해당하는 챌린지를 요청할 때 발생 — (ex: Passkey 옵션 요청 등) */
    REQUEST_CHALLENGE,

    MFA_REQUIRED_CHECK_COMPLETED,

    /** 사용자 자격 증명(비밀번호, 코드 등)을 제출할 때 발생 */
    SUBMIT_CREDENTIAL,

    /** 모든 인증 단계를 통과한 후, 토큰을 발급받기 위해 발생하는 최종 이벤트 */
    ISSUE_TOKEN,

    /** 인증 실패, 복구 경로 요청 시 발생하는 이벤트 — (ex: 이메일 OTP 재전송 등) */
    RECOVER,

    /** 인증 유효 시간이 초과된 경우 발생 — (ex: Passkey 응답 지연) */
    TIMEOUT,

    /** 시스템 내부 오류, 인증 실패, 예외 발생 등으로 인증 흐름을 중단해야 할 때 발생 */
    ERROR
}

