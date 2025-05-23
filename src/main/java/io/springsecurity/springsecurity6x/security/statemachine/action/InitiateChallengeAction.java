package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class InitiateChallengeAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        log.info("Initiating challenge for factor: {} in session: {}",
                factorContext.getCurrentProcessingFactor(), factorContext.getMfaSessionId());

        // Challenge 시작 로직
        // 실제로는 각 팩터별 서비스를 호출하여 challenge를 시작
        // 예: OTT 코드 발송, Passkey challenge 생성 등

        // 상태 업데이트
        context.getExtendedState().getVariables().put("challengeInitiatedAt", System.currentTimeMillis());
    }

    @Override
    public String getActionName() {
        return "InitiateChallengeAction";
    }
}