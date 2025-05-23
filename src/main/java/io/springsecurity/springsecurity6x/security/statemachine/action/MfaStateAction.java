package io.springsecurity.springsecurity6x.security.statemachine.action;

import org.springframework.statemachine.action.Action;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;

/**
 * MFA State Machine Action의 기본 인터페이스
 */
public interface MfaStateAction extends Action<MfaState, MfaEvent> {

    /**
     * Action 실행 전 FactorContext 검증
     * @param context Factor 컨텍스트
     * @return 검증 성공 여부
     */
    default boolean validateContext(FactorContext context) {
        return context != null && context.getMfaSessionId() != null;
    }

    /**
     * Action 이름 (로깅 및 모니터링용)
     * @return Action 이름
     */
    String getActionName();
}
