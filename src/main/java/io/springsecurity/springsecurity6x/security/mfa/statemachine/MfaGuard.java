package io.springsecurity.springsecurity6x.security.mfa.statemachine;

/**
 * MFA 상태 전이의 가드 조건을 정의하는 인터페이스입니다.
 * 이 가드가 true를 반환해야 해당 전이가 발생합니다.
 */
@FunctionalInterface
public interface MfaGuard {

    /**
     * 주어진 컨텍스트에서 상태 전이가 허용되는지 여부를 평가합니다.
     *
     * @param context 현재 MFA 처리 컨텍스트 (FactorContext, 현재 이벤트, 이벤트 페이로드, AuthenticationFlowConfig 등 포함)
     * @return 전이가 허용되면 true, 그렇지 않으면 false
     */
    boolean evaluate(MfaProcessingContext context);
}
