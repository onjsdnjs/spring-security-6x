package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AllFactorsCompletedGuard extends AbstractMfaStateGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        // MFA 정책에 따라 모든 필수 Factor가 완료되었는지 확인
        int requiredFactorCount = getRequiredFactorCount(factorContext);
        int completedFactorCount = factorContext.getCompletedFactors() != null ?
                factorContext.getCompletedFactors().size() : 0;

        boolean allCompleted = completedFactorCount >= requiredFactorCount;

        log.debug("Checking if all factors completed. Required: {}, Completed: {}, Result: {}",
                requiredFactorCount, completedFactorCount, allCompleted);

        return allCompleted;
    }

    private int getRequiredFactorCount(FactorContext context) {
        // MfaPolicyProvider를 통해 필요한 Factor 수 결정
        // 간단한 구현: 기본적으로 1개 Factor 필요
        return 1;
    }

    @Override
    public String getGuardName() {
        return "AllFactorsCompletedGuard";
    }
}