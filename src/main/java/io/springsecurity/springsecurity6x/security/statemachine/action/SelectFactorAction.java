package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class SelectFactorAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        MfaEvent event = context.getEvent();
        AuthType selectedFactor = null;

        // 이벤트에 따라 선택된 팩터 결정
        switch (event) {
            case FACTOR_SELECTED_OTT:
                selectedFactor = AuthType.OTT;
                break;
            case FACTOR_SELECTED_PASSKEY:
                selectedFactor = AuthType.PASSKEY;
                break;
            default:
                log.warn("Unexpected event for factor selection: {}", event);
                return;
        }

        log.info("User selected factor: {} for session: {}", selectedFactor, factorContext.getMfaSessionId());

        // FactorContext 업데이트
        factorContext.setCurrentProcessingFactor(selectedFactor);
        factorContext.setRetryCount(0); // 새 팩터 선택 시 재시도 카운트 리셋
    }

    @Override
    public String getActionName() {
        return "SelectFactorAction";
    }
}