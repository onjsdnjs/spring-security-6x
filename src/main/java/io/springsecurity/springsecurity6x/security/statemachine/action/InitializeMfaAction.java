package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 초기화 액션
 */
@Slf4j
@Component
public class InitializeMfaAction extends AbstractMfaStateAction {

    public InitializeMfaAction(FactorContextStateAdapter factorContextAdapter,
                               StateContextHelper stateContextHelper) {
        super(factorContextAdapter, stateContextHelper);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Initializing MFA for session: {}", sessionId);

        // MFA 초기화 로직
        factorContext.setAttribute("mfaInitializedAt", System.currentTimeMillis());
        factorContext.setRetryCount(0);

        // 초기 상태 설정
        if (factorContext.getCurrentState() == MfaState.NONE) {
            factorContext.changeState(MfaState.START_MFA);
        }

        log.info("MFA initialized successfully for session: {}", sessionId);
    }
}