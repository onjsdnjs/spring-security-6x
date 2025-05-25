package io.springsecurity.springsecurity6x.security.filter.matcher;

/**
 * MFA 요청 타입
 */
public enum MfaRequestType {
    MFA_INITIATE,           // MFA 시작
    SELECT_FACTOR,          // 팩터 선택
    TOKEN_GENERATION,       // 토큰 생성 (OTT 등)
    LOGIN_PROCESSING,       // 로그인 처리
    CHALLENGE_REQUEST,      // 챌린지 요청
    VERIFICATION,           // 검증
    CANCEL,                 // 취소
    UNKNOWN                 // 알 수 없음
}