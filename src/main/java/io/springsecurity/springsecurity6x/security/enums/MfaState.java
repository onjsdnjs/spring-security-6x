package io.springsecurity.springsecurity6x.security.enums;

import lombok.Getter;

@Getter
public enum MfaState {
    /** 초기 상태 또는 MFA 세션이 없는 상태 */
    NONE("MFA 세션 없음"),
    /** 1차 인증 성공, MFA 정책 평가 및 다음 단계 결정 필요 */
    PRIMARY_AUTHENTICATION_COMPLETED("1차 인증 완료"),
    /** 사용자에게 2차 인증 수단 선택 UI 제공 필요 */
    AWAITING_FACTOR_SELECTION("2차 인증 수단 선택 대기"),
    /** 사용자가 특정 Factor를 선택했고, 해당 Factor에 대한 챌린지 시작/UI 로드 필요 */
    AWAITING_FACTOR_CHALLENGE_INITIATION("2차 인증 챌린지 시작 대기"),
    /**
     * 특정 Factor에 대한 챌린지가 사용자에게 제시되었고, 사용자의 응답(예: 코드 입력, Passkey 사용)을
     * Spring Security의 해당 Factor 처리 URL로 전송하여 검증 대기 중임을 나타냄.
     * 이 상태는 플랫폼이 직접 관리하기보다는, 사용자가 해당 Factor의 검증 페이지에 있음을 의미.
     */
    FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION("2차 인증 검증 대기"),
    /** 모든 필수 MFA Factor 검증 완료, 최종 토큰 발급 또는 세션 완료 단계로 진행 */
    ALL_FACTORS_COMPLETED("모든 2차 인증 완료"),
    /** MFA 흐름 최종 실패 (재시도 초과 등) - 터미널 상태 */
    MFA_FAILED_TERMINAL("MFA 최종 실패"),
    /** MFA 세션 시간 초과 - 터미널 상태 */
    MFA_SESSION_EXPIRED("MFA 세션 만료");

    private final String description;

    MfaState(String description) {
        this.description = description;
    }

    public boolean isTerminal() {
        return this == MFA_FAILED_TERMINAL || this == MFA_SESSION_EXPIRED || this == ALL_FACTORS_COMPLETED /* 최종 성공도 터미널로 간주 가능 */;
    }
}