package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaPolicyGuard extends AbstractMfaStateGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        // MFA 정책에 따라 추가 인증이 필요한지 확인
        boolean mfaRequired = factorContext.isMfaRequiredAsPerPolicy();

        // 이벤트에 따른 추가 검증
        MfaEvent event = context.getEvent();
        if (event == MfaEvent.MFA_REQUIRED_SELECT_FACTOR ||
                event == MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE) {
            return mfaRequired;
        }

        // Factor 완료 후 추가 Factor가 필요한지 확인
        if (event == MfaEvent.FACTOR_VERIFIED_SUCCESS) {
            // 모든 필수 Factor가 완료되었는지 확인
            return !allRequiredFactorsCompleted(factorContext);
        }

        return true;
    }

    private boolean allRequiredFactorsCompleted(FactorContext context) {
        // MfaPolicyProvider를 통해 필요한 모든 Factor가 완료되었는지 확인
        // 간단한 구현: 최소 1개 이상의 Factor가 완료되었는지 확인
        return context.getCompletedFactors() != null && !context.getCompletedFactors().isEmpty();
    }

    @Override
    public String getGuardName() {
        return "MfaPolicyGuard";
    }
}
