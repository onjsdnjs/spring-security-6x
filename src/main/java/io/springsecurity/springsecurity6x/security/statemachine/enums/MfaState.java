package io.springsecurity.springsecurity6x.security.statemachine.enums;

import lombok.Getter;

@Getter
public enum MfaState {

    // --- 기본 상태 ---
    IDLE("아직 시작 안함"),
    START_MFA("MFA 흐름 시작 (1차 인증 성공 직후)"),
    END_MFA("MFA 흐름 완전 종료 (성공, 실패, 취소 등 모든 터미널 상태 이후의 개념적 종료)"), // Configurator에서 사용

    // --- 1차 인증 후 ---
    PRIMARY_AUTHENTICATION_SUCCESSFUL("1차 인증 성공, 2차 요소 결정 필요"),

    // --- 2차 요소 선택 및 처리 과정 ---
    AWAITING_FACTOR_SELECTION("2차 인증 수단 선택 대기"),
    // FACTOR_SELECTED는 이벤트로 처리하고 바로 다음 상태로 가는 것이 일반적이므로 생략 가능
    // FACTOR_SELECTED("사용자가 2차 인증 요소 선택 완료"), // MfaStateMachineConfigurator.java에서 직접 사용하지 않음

    AWAITING_FACTOR_CHALLENGE_INITIATION("2차 인증 챌린지 시작/UI 로드 대기"), // Configurator에서 사용
    FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION("2차 인증 챌린지 제시, 사용자 입력/검증 대기"), // Configurator에서 사용
    FACTOR_VERIFICATION_IN_PROGRESS("2차 인증 요소 검증 진행 중"), // Configurator에서 사용

    // 개별 팩터 검증 대기 상태
    AWAITING_OTT_VERIFICATION("OTT 코드 입력 대기 (코드 발송 후)"),
    AWAITING_PASSKEY_VERIFICATION("Passkey 검증 대기 (Assertion Options 생성 후)"),

    // 개별 팩터 검증 성공 상태 (이들은 보통 다음 단계로 가기 위한 임시 상태이거나, checkAllFactorsCompleted의 조건이 됨)
    // OTT_VERIFICATION_SUCCESSFUL("OTT 코드 검증 성공"), // MfaStateMachineConfigurator.java에서 직접 사용하지 않음
    // PASSKEY_VERIFICATION_SUCCESSFUL("Passkey 검증 성공"), // MfaStateMachineConfigurator.java에서 직접 사용하지 않음

    // --- MFA 흐름 결과 상태 ---
    ALL_FACTORS_COMPLETED("모든 필수 MFA 요소 검증 완료"), // 최종 성공 직전
    MFA_SUCCESSFUL("최종 인증 성공 (모든 처리 완료)"),     // Configurator에서 사용

    MFA_FAILURE("MFA 인증 실패 (일반)"), // 제공된 MfaState.java에 이미 있음
    MFA_FAILED_TERMINAL("MFA 최종 실패 (재시도 초과 등)"), // Configurator에서 사용

    MFA_CANCELLED("사용자에 의한 MFA 흐름 취소"), // Configurator에서 사용

    // --- 기타 상태 ---
    MFA_CONFIGURATION_REQUIRED("사용자 MFA 설정 필요"), // 제공된 MfaState.java에 이미 있음
    MFA_SESSION_EXPIRED("MFA 세션 만료"),             // 제공된 MfaState.java에 이미 있음
    MFA_SESSION_INVALIDATED("MFA 세션 무효화"),       // 제공된 MfaState.java에 이미 있음

    FACTOR_SELECTED(""),              // 사용자가 2차 인증 요소 선택 완료

    OTT_VERIFICATION_SUCCESSFUL(""),  // OTT 코드 검증 성공
    PASSKEY_VERIFICATION_SUCCESSFUL(""), // Passkey 검증 성공
    // TODO: 다른 MFA 요소(예: Recovery Code) 상태 추가 가능

    // MFA 흐름 완료 상태
    MFA_COMPLETED_PARTIALLY(""),    // 일부 요소만 완료되었으나, 정책에 따라 다음 단계 진행 또는 추가 요소 필요 (예: 계층적 상태에서 사용)

    // MFA 흐름 실패/종료 상태
    MFA_RETRY_LIMIT_EXCEEDED(""),   // 재시도 횟수 초과

    /** 초기 상태 또는 MFA 세션이 없는 상태 */
    NONE("MFA 세션 없음"), // 사용: FactorContext 로드 실패 시 또는 초기화 전

    /** 1차 인증 성공, MFA 정책 평가 및 다음 단계 결정 필요.
     * 1차 인증 성공 핸들러에서 이 상태를 거쳐 즉시 다음 상태로 전이되어야 함.
     */
    PRIMARY_AUTHENTICATION_COMPLETED("1차 인증 완료"),

    /** 사용자에게 2차 인증 수단 선택 UI 제공 필요.
     * MfaContinuationFilter가 /mfa/select-factor 요청 처리 시 이 상태 확인.
     * MfaApiController 에서 Factor 선택 후 AWAITING_FACTOR_CHALLENGE_INITIATION으로 전이.
     */

    FACTOR_CHALLENGE_SENT_AWAITING_UI("2차 인증 챌린지 요청"),

    /** [사용 빈도 낮음/재검토] 실제 챌린지가 발송/생성 완료된 특정 시점을 나타낼 수 있으나,
     * AWAITING_FACTOR_CHALLENGE_INITIATION 후 바로 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION 으로
     * 전이하는 것이 더 일반적일 수 있음. 현재는 유지.
     */
    FACTOR_CHALLENGE_INITIATED("실제 챌린지 발송"),

    /** [삭제 또는 통합 고려] Passkey Conditional UI와 같은 자동 인증 시도 기능 구현 시 필요.
     * 현재 핵심 MFA 흐름에서는 사용되지 않을 수 있음.
     */
    AUTO_ATTEMPT_FACTOR_PENDING("자동 인증 시도 대기"),
    /** [삭제 또는 통합 고려] Passkey Conditional UI와 같은 자동 인증 시도 기능 구현 시 필요. */
    AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING("자동 인증 시도 검증 중"),

    /** 사용자가 Factor 검증 정보를 제출했고, 시스템이 검증 중인 상태.
     * MfaStepFilterWrapper가 실제 Factor 인증 필터로 위임하면, 해당 필터가 이 상태로 진입(또는 내부적으로 처리).
     * Factor 인증 필터의 성공/실패 핸들러가 다음 상태(AWAITING_FACTOR_SELECTION, AWAITING_FACTOR_CHALLENGE_INITIATION, ALL_FACTORS_COMPLETED, MFA_FAILED_TERMINAL)로 전이.
     */
    FACTOR_VERIFICATION_PENDING("Factor 검증 진행"),

    /** [ALL_FACTORS_COMPLETED와 통합 고려] 특정 Factor 하나가 성공적으로 검증된 직후의 상태.
     * MFA Factor 성공 핸들러에서 이 상태를 거쳐 다음 Factor 또는 ALL_FACTORS_COMPLETED로 전이.
     */
    FACTOR_VERIFICATION_COMPLETED("인증 요소 검증 완료"),

    /** 모든 필수 MFA Factor 검증 완료, 최종 토큰 발급 또는 세션 완료 단계로 진행.
     * 최종 성공 핸들러가 이 상태를 보고 토큰 발급 후 MFA_COMPLETED_TOKEN_ISSUED로 전이.
     */

    /** [ALL_FACTORS_COMPLETED로 통합 또는 MFA_COMPLETED_TOKEN_ISSUED로 대체 고려]
     * 모든 인증(1차 및 모든 MFA) 완료 후 토큰 발급/세션 생성만 남은 상태.
     */
    TOKEN_ISSUANCE_REQUIRED("최종 토큰 발급 대기"),

    /** [MFA_COMPLETED_TOKEN_ISSUED로 대체 고려] MFA 흐름 최종 성공 (토큰 발급/세션 생성 완료) - 터미널 상태 */
    MFA_COMPLETE("MFA 최종 인증 성공"),

    /** MFA 처리 중 예상치 못한 시스템 오류 발생 - 터미널 상태 */
    MFA_SYSTEM_ERROR("MFA 시스템 오류"),

    /** [ALL_FACTORS_COMPLETED와 중복] 모든 MFA Factor 검증 완료. 삭제 또는 ALL_FACTORS_COMPLETED로 통일 권장. */
    MFA_VERIFICATION_COMPLETED("모든 MFA Factor 검증 완료"), // 설명 중복
    /** [MFA_FAILED_TERMINAL과 중복] MFA 최종 실패. 삭제 또는 MFA_FAILED_TERMINAL로 통일 권장. */
    MFA_FAILURE_TERMINAL("MFA 최종 실패"), MFA_NOT_REQUIRED("MFA 대상자 아님");// 설명 중복 및 이름 중복


    private final String description;

    MfaState(String description) {
        this.description = description;
    }

    public boolean isTerminal() {
        return this == MFA_COMPLETE || // MFA_COMPLETED_TOKEN_ISSUED로 대체되면 해당 값 사용
                this == MFA_FAILURE_TERMINAL || // MFA_FAILED_TERMINAL과 동일
                this == MFA_FAILED_TERMINAL ||
                this == MFA_SESSION_EXPIRED ||
                this == MFA_SESSION_INVALIDATED ||
                this == MFA_SYSTEM_ERROR ||
                this == ALL_FACTORS_COMPLETED; // ALL_FACTORS_COMPLETED는 최종 성공 직전 상태이므로 터미널이 아님.
        // MFA_COMPLETED_TOKEN_ISSUED 가 터미널.
    }

    // isChallengePhase(), isVerificationPhase() 등 헬퍼 메소드 추가 가능
}