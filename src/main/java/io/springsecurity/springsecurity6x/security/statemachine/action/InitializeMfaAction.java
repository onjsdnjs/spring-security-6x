package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 초기화 액션
 */
@Slf4j
@Component
public class InitializeMfaAction extends AbstractMfaStateAction {

    public InitializeMfaAction(FactorContextStateAdapter factorContextAdapter) {
        super(factorContextAdapter);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Initializing MFA for session: {}, user: {}",
                sessionId, factorContext.getUsername());

        // 원래 로직 그대로, 단지 저장 방식만 개선
        factorContext.setAttribute("mfaInitializedAt", System.currentTimeMillis());
        factorContext.setAttribute("primaryAuthCompleted", true);

        HttpServletRequest request = (HttpServletRequest) context.getMessageHeader("request");
        if (request != null) {
            factorContext.setAttribute("userAgent", request.getHeader("User-Agent"));
            factorContext.setAttribute("clientIp", request.getRemoteAddr());
        }

        log.info("MFA initialization completed for session: {}", sessionId);
    }
}