package io.springsecurity.springsecurity6x.security.enums;

/**
 * MFA(Multi-Factor Authentication) 상태 열거형
 * 인증 진행 흐름에서 사용자의 현재 위치(상태)를 나타내며,
 * 상태 머신(State Machine)에 따라 이벤트에 의해 전이된다.
 */
public enum MfaState {

    /** 인증 시작 전 초기 상태 */
    INIT,

    /** [1단계] 웹 로그인(Form) 인증 요청 상태 — 로그인 화면을 표시해야 함 */
    FORM_CHALLENGE,

    /** [1단계] 웹 로그인(Form) 인증 완료 상태 — 사용자 자격 증명이 제출되고 검증 완료됨 */
    FORM_SUBMITTED,

    /** [1단계] REST API 기반 로그인 인증 요청 상태 — 비동기 클라이언트에서 로그인 요청 */
    REST_CHALLENGE,

    /** [1단계] REST 로그인 인증 완료 상태 — API 기반 인증 정보가 제출되고 검증 완료됨 */
    REST_SUBMITTED,

    /** [2단계] OTP 또는 이메일 코드(One-Time Token) 인증 요청 상태 — 사용자가 코드를 입력해야 함 */
    OTT_CHALLENGE,

    /** [2단계] OTP 또는 이메일 인증 완료 상태 — 사용자가 발송받은 코드를 성공적으로 제출함 */
    OTT_SUBMITTED,

    /** [3단계] Passkey(WebAuthn 생체 인증) 요청 상태 — 인증 장치와의 연결을 요청함 */
    PASSKEY_CHALLENGE,

    /** [3단계] Passkey 인증 완료 상태 — 장치로부터 받은 응답이 유효함 */
    PASSKEY_SUBMITTED,

    /** 모든 인증 단계 완료 후, 토큰 발급이 수행되어야 하는 상태 */
    TOKEN_ISSUANCE,

    /** 인증 및 토큰 발급이 모두 완료된 최종 상태 */
    COMPLETED,

    /** 인증 흐름 도중 오류, 디바이스 분실, 제한 횟수 초과 등으로 복구 플로우에 진입한 상태 */
    RECOVERY
}


