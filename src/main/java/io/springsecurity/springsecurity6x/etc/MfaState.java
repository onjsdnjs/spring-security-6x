package io.springsecurity.springsecurity6x.etc;

import lombok.Getter;

@Getter
public enum MfaState {

    // --- 기본 상태 ---
    NONE("MFA 세션 없음"),

    // --- 1차 인증 후 ---
    PRIMARY_AUTHENTICATION_COMPLETED("1차 인증 완료"),

    // --- MFA 진행 상태 ---
    START_MFA("MFA 흐름 시작"),
    MFA_NOT_REQUIRED("MFA 불필요"),
    AWAITING_FACTOR_SELECTION("2차 인증 수단 선택 대기"),
    FACTOR_SELECTED("사용자가 2차 인증 요소 선택 완료"),
    AWAITING_FACTOR_CHALLENGE_INITIATION("2차 인증 챌린지 시작 대기"),
    FACTOR_CHALLENGE_INITIATED("실제 챌린지 발송"),
    FACTOR_CHALLENGE_SENT_AWAITING_UI("2차 인증 챌린지 요청"),
    FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION("2차 인증 챌린지 제시, 사용자 입력 대기"),
    FACTOR_VERIFICATION_PENDING("Factor 검증 진행"),
    FACTOR_VERIFICATION_COMPLETED("인증 요소 검증 완료"),

    // --- MFA 최종 상태 ---
    ALL_FACTORS_COMPLETED("모든 필수 MFA 요소 검증 완료"),
    MFA_SUCCESSFUL("최종 인증 성공"),

    // --- 실패/종료 상태 ---
    MFA_FAILED_TERMINAL("MFA 최종 실패"),
    MFA_RETRY_LIMIT_EXCEEDED("재시도 횟수 초과"),
    MFA_CANCELLED("사용자에 의한 MFA 흐름 취소"),
    MFA_SESSION_EXPIRED("MFA 세션 만료"),
    MFA_CONFIGURATION_REQUIRED("사용자 MFA 설정 필요"),
    MFA_SYSTEM_ERROR("MFA 시스템 오류");

    private final String description;

    MfaState(String description) {
        this.description = description;
    }

    public boolean isTerminal() {
        return this == MFA_SUCCESSFUL ||
                this == MFA_FAILED_TERMINAL ||
                this == MFA_SESSION_EXPIRED ||
                this == MFA_CANCELLED ||
                this == MFA_SYSTEM_ERROR ||
                this == MFA_NOT_REQUIRED;
    }

    public boolean isWaitingForUserAction() {
        return this == AWAITING_FACTOR_SELECTION ||
                this == FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
    }
}