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

    FACTOR_CHALLENGE_INITIATED("실제 챌린지 발송"),

    // 아래는 이전 제안에서 누락되었던, 중요한 추가 상태들입니다.
    // 실제 프로젝트의 MfaState.java 파일에 아래와 유사한 상태들이 정의되어 있다고 가정합니다.
    // (사용자가 제공한 파일 내용을 기반으로 아래 내용을 보완 또는 대체해야 합니다.)

    /** MFA가 필요하며, 자동 시도 가능한 Factor가 있는 경우 (예: Passkey Conditional UI) */
    AUTO_ATTEMPT_FACTOR_PENDING("자동 인증 시도 대기"), // 이 부분은 사용자 제공 파일에 없을 수 있습니다. 필요시 추가.
    /** 자동 시도 Factor에 대한 검증 진행 중 */
    AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING("자동 인증 시도 검증 중"), // 이 부분은 사용자 제공 파일에 없을 수 있습니다. 필요시 추가.

    FACTOR_VERIFICATION_PENDING("Factor 검증 진행"),
    /** (단일 또는 다중) Factor 검증 성공 후, 추가 Factor 필요 여부 또는 최종 완료 판단 대기 상태 */
    FACTOR_VERIFICATION_COMPLETED("인증 요소 검증 완료"), // 이 부분은 ALL_FACTORS_COMPLETED와 유사/통합될 수 있습니다.

    /** 모든 필수 MFA Factor 검증 완료, 최종 토큰 발급 또는 세션 완료 단계로 진행 */
    ALL_FACTORS_COMPLETED("모든 2차 인증 완료"), // 사용자가 제공한 파일에 이미 존재

    /** 모든 인증(1차 및 모든 MFA) 완료 후 토큰 발급/세션 생성만 남은 상태 */
    TOKEN_ISSUANCE_REQUIRED("최종 토큰 발급 대기"), // 이 부분은 사용자 제공 파일에 없을 수 있습니다. 필요시 추가.

    /** MFA 흐름 최종 성공 (토큰 발급/세션 생성 완료) - 터미널 상태 */
    MFA_FULLY_COMPLETED("MFA 최종 인증 성공"), // 이 부분은 사용자 제공 파일에 없을 수 있습니다. 필요시 추가.

    /** MFA 흐름 최종 실패 (재시도 초과 등) - 터미널 상태 */
    MFA_FAILED_TERMINAL("MFA 최종 실패"), // 사용자가 제공한 파일에 이미 존재
    /** MFA 세션 시간 초과 - 터미널 상태 */
    MFA_SESSION_EXPIRED("MFA 세션 만료"), // 사용자가 제공한 파일에 이미 존재
    /** MFA 세션이 유효하지 않거나 의도적으로 무효화된 경우 (예: 로그아웃, 다른 세션에서의 로그인) - 터미널 상태 */
    MFA_SESSION_INVALIDATED("MFA 세션 무효화"), // 이 부분은 사용자 제공 파일에 없을 수 있습니다. 필요시 추가.
    /** MFA 처리 중 예상치 못한 시스템 오류 발생 - 터미널 상태 */
    MFA_SYSTEM_ERROR("MFA 시스템 오류"),

    MFA_VERIFICATION_COMPLETED("모든 MFA Factor 검증 완료"),
    MFA_FAILURE_TERMINAL("MFA 최종 실패");

    // 이 부분은 사용자 제공 파일에 없을 수 있습니다. 필요시 추가.


    private final String description;

    MfaState(String description) {
        this.description = description;
    }

    public boolean isTerminal() {
        return this == MFA_FULLY_COMPLETED ||
                this == MFA_FAILURE_TERMINAL ||
                this == MFA_FAILED_TERMINAL ||
                this == MFA_SESSION_EXPIRED ||
                this == MFA_SESSION_INVALIDATED ||
                this == MFA_SYSTEM_ERROR ||
                this == ALL_FACTORS_COMPLETED; // ALL_FACTORS_COMPLETED도 최종 성공으로 간주 시 터미널
    }
}