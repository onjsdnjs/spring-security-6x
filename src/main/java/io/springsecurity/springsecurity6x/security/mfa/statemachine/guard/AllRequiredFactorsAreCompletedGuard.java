package io.springsecurity.springsecurity6x.security.mfa.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaGuard;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component("allRequiredFactorsAreCompletedGuard") // 빈 이름 명시
@RequiredArgsConstructor
public class AllRequiredFactorsAreCompletedGuard implements MfaGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    public boolean evaluate(MfaProcessingContext context) {
        log.debug("Evaluating AllRequiredFactorsAreCompletedGuard for user: {}", context.getFactorContext().getUsername());
        // MfaPolicyProvider.checkAllFactorsCompleted는 상태를 변경하므로 직접 호출하지 않고,
        // FactorContext의 isFullyAuthenticated() 또는 유사한 상태 확인 메소드를 사용하거나,
        // MfaPolicyProvider에 순수하게 조건만 확인하는 메소드가 필요.
        // 여기서는 checkAllFactorsCompleted가 상태를 변경하고, 그 결과를 FactorContext가 반영한다고 가정.
        // 또는, 이 Guard가 호출되는 시점에는 이미 checkAllFactorsCompleted가 호출된 후라고 가정.
        // 더 나은 방법: MfaPolicyProvider에 boolean isAllFactorsCompleted(FactorContext, AuthenticationFlowConfig) 메소드 추가.
        // 지금은 FactorContext의 상태를 확인하는 것으로 가정.
        mfaPolicyProvider.checkAllFactorsCompleted(context.getFactorContext(), context.getFlowConfig()); // 상태 갱신
        boolean result = context.getFactorContext().isFullyAuthenticated(); // MfaState.MFA_FULLY_COMPLETED 확인
        log.debug("AllRequiredFactorsAreCompletedGuard result: {}", result);
        return result;
    }
}
