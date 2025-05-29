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

        // 현재 팩터가 없으면 에러
        if (factorContext.getCurrentProcessingFactor() == null) {
            throw new IllegalStateException("No factor selected for challenge initiation");
        }

        String factorType = factorContext.getCurrentProcessingFactor().name();

        // 팩터별 챌린지 처리
        switch (factorType) {
            case "OTT":
                // OTT 코드 발송
                factorContext.setAttribute("ottCodeSent", true);
                break;

            case "PASSKEY":
                // Passkey 옵션 생성
                factorContext.setAttribute("passkeyOptionsGenerated", true);
                break;
        }

        // 성공 플래그 설정 (Guard에서 사용)
        context.getExtendedState().getVariables()
                .put("challengeInitiationSuccess", true);
    }
}