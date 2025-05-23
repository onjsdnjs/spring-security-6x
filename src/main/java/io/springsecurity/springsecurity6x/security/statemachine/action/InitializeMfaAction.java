package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class InitializeMfaAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        log.info("Initializing MFA flow for user: {}", factorContext.getUsername());

        // MFA 플로우 초기화 로직
        factorContext.setRetryCount(0);
        factorContext.setLastError(null);

        // 사용 가능한 팩터 확인 및 설정은 이미 되어 있을 것으로 가정
        log.debug("Available factors: {}", factorContext.getAvailableFactors());
    }

    @Override
    public String getActionName() {
        return "InitializeMfaAction";
    }
}