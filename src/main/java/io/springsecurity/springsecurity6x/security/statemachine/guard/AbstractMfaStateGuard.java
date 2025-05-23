package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.beans.factory.annotation.Autowired;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import org.springframework.statemachine.guard.Guard;

/**
 * MFA State Machine Guard의 기본 추상 클래스 (Spring State Machine 4.0.0)
 */
@Slf4j
public abstract class AbstractMfaStateGuard implements Guard<MfaState, MfaEvent>, MfaStateGuard {

    @Autowired
    private StateContextHelper contextHelper;

    @Override
    public boolean evaluate(StateContext<MfaState, MfaEvent> context) {
        String sessionId = (String) context.getMessageHeaders().get("sessionId");
        log.debug("Evaluating guard {} for session {}", getGuardName(), sessionId);

        try {
            // FactorContext 추출
            FactorContext factorContext = contextHelper.extractFactorContext(context);

            if (factorContext == null) {
                log.warn("No FactorContext found for guard evaluation");
                return false;
            }

            // 구체적인 가드 로직 실행
            boolean result = doEvaluate(context, factorContext);

            log.debug("Guard {} evaluated to: {}", getGuardName(), result);
            return result;

        } catch (Exception e) {
            log.error("Error evaluating guard {}: {}", getGuardName(), e.getMessage(), e);
            return false;
        }
    }

    /**
     * 구체적인 가드 로직 구현
     */
    protected abstract boolean doEvaluate(StateContext<MfaState, MfaEvent> context, FactorContext factorContext);

    /**
     * StateContext 에서 FactorContext 추출 (deprecated - contextHelper 사용)
     */
    @Deprecated
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return contextHelper.extractFactorContext(context);
    }

    /**
     * Guard의 부정 (negate) 버전 생성
     */
    public Guard<MfaState, MfaEvent> negate() {
        return context -> !this.evaluate(context);
    }
}