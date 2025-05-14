package io.springsecurity.springsecurity6x.security.enums;

/**
 * 새로운 MFA(Multi-Factor Authentication) 상태 열거형.
 * 사용자의 선택과 다양한 인증 수단을 지원하는 유연한 흐름을 위해 재설계되었습니다.
 */
public enum MfaState {

    // --- 초기/1차 인증 완료 단계 ---
    /** 1차 인증(ID/PW) 성공 후 초기 MFA 상태. MFA 필요 여부 및 정책 확인 전. */
    PRIMARY_AUTHENTICATION_COMPLETED,

    // --- 자동 시도 (예: Passkey Conditional UI) 단계 ---
    /**
     * 자동 시도 가능성이 있는 Factor(예: Passkey Conditional UI)에 대한 사용자 인터랙션 대기 또는 백그라운드 확인 중.
     * 이 상태에서 사용자가 직접 Factor를 선택하여 건너뛸 수도 있음.
     */
    AUTO_ATTEMPT_FACTOR_PENDING,
    /** 자동 시도 Factor에 대한 검증 진행 중. */
    AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING,

    // --- MFA Factor 선택 단계 ---
    /** 사용 가능한 MFA Factor 목록을 사용자에게 제시하고 선택을 기다리는 상태. */
    AWAITING_MFA_FACTOR_SELECTION,

    // --- 각 Factor 별 챌린지/검증 단계 ---
    /** 특정 MFA Factor에 대한 챌린지(예: Passkey 챌린지 생성, OTT 코드 발송)가 요청되었거나 진행 중인 상태. */
    FACTOR_CHALLENGE_INITIATED, // Generic state for challenge initiation
    /** 특정 MFA Factor에 대한 사용자 입력(예: Passkey 서명, OTT 코드)을 받아 검증을 진행 중인 상태. */
    FACTOR_VERIFICATION_PENDING, // Generic state for verification

    // --- 최종 상태 ---
    TOKEN_ISSUANCE_REQUIRED,
    /** 모든 MFA 요구사항이 충족되어 최종 인증(토큰 발급 등)으로 진행될 수 있는 상태. */
    MFA_VERIFICATION_COMPLETED,
    /** MFA 과정이 완전히 성공하고 토큰까지 발급된 최종 완료 상태. */
    MFA_FULLY_COMPLETED,
    /** MFA 과정에서 최종적으로 실패하여 더 이상 진행할 수 없는 상태. */
    MFA_FAILURE_TERMINAL,

    // --- 공통 관리 상태 ---
    /** 현재 MFA 세션이 만료되었거나 유효하지 않아 재시작 또는 실패 처리해야 하는 상태. */
    MFA_SESSION_INVALIDATED,
    /** 시스템 오류 또는 예기치 않은 문제 발생으로 MFA 진행이 어려운 상태. */
    MFA_SYSTEM_ERROR;

    /**
     * 이 상태가 최종적인 성공 또는 실패 상태인지 확인합니다.
     * @return 터미널 상태이면 true
     */
    public boolean isTerminal() {
        return this == MFA_FULLY_COMPLETED ||
                this == MFA_FAILURE_TERMINAL ||
                this == MFA_SESSION_INVALIDATED ||
                this == MFA_SYSTEM_ERROR;
    }

    /**
     * 이 상태가 사용자의 Factor 선택을 기다리는 상태인지 확인합니다.
     * @return Factor 선택 대기 상태이면 true
     */
    public boolean isAwaitingFactorSelection() {
        return this == AWAITING_MFA_FACTOR_SELECTION;
    }

    /**
     * 이 상태가 특정 Factor에 대한 챌린지 또는 검증 과정에 있는지 확인합니다.
     * @return Factor 처리 중이면 true
     */
    public boolean isInFactorProcessing() {
        return this == FACTOR_CHALLENGE_INITIATED || this == FACTOR_VERIFICATION_PENDING;
    }
}