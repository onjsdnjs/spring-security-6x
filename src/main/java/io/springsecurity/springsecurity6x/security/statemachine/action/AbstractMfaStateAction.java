package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.beans.factory.annotation.Autowired;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import org.springframework.statemachine.action.Action;

/**
 * MFA State Machine Action의 기본 추상 클래스 (Spring State Machine 4.0.0)
 */
@Slf4j
public abstract class AbstractMfaStateAction implements Action<MfaState, MfaEvent>, MfaStateAction {

    @Autowired
    private StateContextHelper contextHelper;

    @Override
    public void execute(StateContext<MfaState, MfaEvent> context) {
        String sessionId = (String) context.getMessageHeaders().get("sessionId");
        log.debug("Executing action {} for session {}", getActionName(), sessionId);

        try {
            // FactorContext 추출
            FactorContext factorContext = contextHelper.extractFactorContext(context);

            if (!validateContext(factorContext)) {
                log.error("Invalid FactorContext for action {}", getActionName());
                throw new IllegalStateException("Invalid FactorContext");
            }

            // 구체적인 액션 실행
            doExecute(context, factorContext);

            // 변경사항을 State Machine 변수에 반영
            contextHelper.updateStateContext(context, factorContext);

        } catch (Exception e) {
            log.error("Error executing action {}: {}", getActionName(), e.getMessage(), e);
            // Spring State Machine 4.0.0에서는 예외를 throw하면 transition이 중단됨
            throw new RuntimeException("Action execution failed: " + getActionName(), e);
        }
    }

    /**
     * 구체적인 액션 로직 구현
     */
    protected abstract void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext);

    /**
     * StateContext에서 FactorContext 추출 (deprecated - contextHelper 사용)
     */
    @Deprecated
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return contextHelper.extractFactorContext(context);
    }

    /**
     * FactorContext 변경사항을 State Machine 변수에 반영 (deprecated - contextHelper 사용)
     */
    @Deprecated
    protected void updateStateMachineVariables(StateContext<MfaState, MfaEvent> context,
                                               FactorContext factorContext) {
        contextHelper.updateStateContext(context, factorContext);
    }

    /**
     * 구체적인 액션 로직 구현
     */
    protected abstract void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext);

    /**
     * StateContext에서 FactorContext 추출
     */
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        // Extended State Variables에서 재구성하거나
        // Message Header에서 전달된 정보로 조회
        // 실제 구현은 ContextPersistence를 통해 로드해야 할 수도 있음
        return null; // TODO: 구현 필요
    }

    /**
     * FactorContext 변경사항을 State Machine 변수에 반영
     */
    protected void updateStateMachineVariables(StateContext<MfaState, MfaEvent> context,
                                               FactorContext factorContext) {
        context.getExtendedState().getVariables().put("lastUpdated", System.currentTimeMillis());
        // 추가 변수 업데이트
    }
}