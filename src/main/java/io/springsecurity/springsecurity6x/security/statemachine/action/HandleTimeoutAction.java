package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class HandleTimeoutAction extends AbstractMfaStateAction {

    public HandleTimeoutAction(FactorContextStateAdapter factorContextAdapter, StateContextHelper stateContextHelper) {
        super(factorContextAdapter, stateContextHelper);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        MfaEvent event = context.getEvent();

        log.info("Handling timeout for session: {}, event: {}", sessionId, event);

        if (event == MfaEvent.SESSION_TIMEOUT) {
            factorContext.setAttribute("sessionTimeoutAt", System.currentTimeMillis());
            factorContext.changeState(MfaState.MFA_SESSION_EXPIRED);
        } else if (event == MfaEvent.CHALLENGE_TIMEOUT) {
            factorContext.setAttribute("challengeTimeoutAt", System.currentTimeMillis());
            // 챌린지 관련 속성 정리
            factorContext.removeAttribute("challengeInitiatedAt");
            factorContext.removeAttribute("ottCodeSent");
        }
    }
}
