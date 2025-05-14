package io.springsecurity.springsecurity6x.security.enums;


public enum MfaEvent {
    // 기존 이벤트들
    REQUEST_CHALLENGE,    // 특정 Factor에 대한 챌린지 생성/요청 (예: Passkey options 요청, OTT 코드 생성 요청)
    SUBMIT_CREDENTIAL,    // 사용자가 자격 증명(비밀번호, 코드, Passkey 응답 등)을 제출
    ISSUE_TOKEN,          // 모든 인증 완료 후 토큰 발급 요청
    RECOVER,              // 복구 흐름 시작 요청
    TIMEOUT,              // 인증 유효 시간 초과
    ERROR,                // 일반 오류

    // 새로운 MFA 흐름을 위한 이벤트 추가
    PRIMARY_AUTH_SUCCESS, // 1차 인증 성공 (MFA 흐름 시작점)
    AUTO_ATTEMPT_SKIPPED, // 자동 시도 Factor 건너뛰기 또는 실패/미지원
    FACTOR_SELECTED,      // 사용자가 MFA Factor 선택
    CHALLENGE_INITIATED,  // Factor 챌린지 시작됨 (예: Passkey Conditional UI 표시됨)
    CHALLENGE_DELIVERED,  // Factor 챌린지 전달 완료 (예: OTT 코드 발송 성공)
    CHALLENGE_DELIVERY_FAILURE, // Factor 챌린지 전달 실패
    VERIFICATION_SUCCESS, // 특정 Factor 검증 성공
    VERIFICATION_FAILURE, // 특정 Factor 검증 실패
    SELECT_MFA_METHOD,    // (AUTO_ATTEMPT_FACTOR_PENDING 등에서) 다른 MFA 방법 선택 화면으로 가기 요청
    SKIP_AUTO_ATTEMPT     // (AUTO_ATTEMPT_FACTOR_PENDING 등에서) 자동 시도 건너뛰기 요청
}

