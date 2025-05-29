package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 실패 처리 액션
 */
@Slf4j
@Component
public class HandleFailureAction extends AbstractMfaStateAction {

    public HandleFailureAction(FactorContextStateAdapter factorContextAdapter,
                               StateContextHelper stateContextHelper) {
        super(factorContextAdapter, stateContextHelper);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Handling MFA failure for session: {}", sessionId);

        String failureReason = (String) context.getMessageHeader("failureReason");
        if (failureReason == null) {
            failureReason = (String) context.getExtendedState().getVariables().get("lastError");
        }

        factorContext.setLastError(failureReason != null ? failureReason : "Unknown error");
        factorContext.setAttribute("lastFailureTime", System.currentTimeMillis());

        int retryCount = factorContext.getRetryCount();
        factorContext.setRetryCount(retryCount + 1);

        Integer maxRetries = (Integer) context.getExtendedState().getVariables().get("maxRetries");
        if (maxRetries == null) {
            maxRetries = 3;
        }

        if (factorContext.getRetryCount() >= maxRetries) {
            log.warn("Max retry attempts exceeded for session: {}", sessionId);
            // factorContext.changeState(MfaState.MFA_RETRY_LIMIT_EXCEEDED); // 제거!
            // State Machine이 전이를 관리하도록 함
        } else {
            log.info("Retry attempt {} of {} for session: {}",
                    factorContext.getRetryCount(), maxRetries, sessionId);
        }
    }
}