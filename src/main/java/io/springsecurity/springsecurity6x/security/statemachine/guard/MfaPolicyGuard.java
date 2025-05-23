package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 정책 기반 Guard
 * MFA 정책에 따라 추가 인증이 필요한지 판단
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaPolicyGuard extends AbstractMfaStateGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();

        try {
            // MFA가 정책상 필요한지 확인
            if (!factorContext.isMfaRequiredAsPerPolicy()) {
                log.debug("MFA not required per policy for session: {}", sessionId);
                return false;
            }

            // 완료된 팩터가 있는지 확인
            boolean hasCompletedFactors = factorContext.getCompletedFactors() != null &&
                    !factorContext.getCompletedFactors().isEmpty();

            // 사용 가능한 팩터가 있는지 확인
            boolean hasAvailableFactors = !factorContext.getRegisteredMfaFactors().isEmpty();

            log.debug("MFA policy evaluation for session {}: hasCompletedFactors={}, hasAvailableFactors={}",
                    sessionId, hasCompletedFactors, hasAvailableFactors);

            // MFA가 필요하고 사용 가능한 팩터가 있으면 true
            return hasAvailableFactors;

        } catch (Exception e) {
            log.error("Error evaluating MFA policy for session: {}", sessionId, e);
            return false;
        }
    }

    @Override
    public String getFailureReason() {
        return "MFA policy requirements not met";
    }

    @Override
    public String getGuardName() {
        return "MfaPolicyGuard";
    }

    /**
     * 모든 필수 팩터가 완료되었는지 확인
     */
    public boolean allRequiredFactorsCompleted(FactorContext factorContext) {
        if (factorContext.getCompletedFactors() == null ||
                factorContext.getCompletedFactors().isEmpty()) {
            return false;
        }

        // MfaPolicyProvider를 통해 필요한 팩터 수 확인
        String userId = factorContext.getUsername();
        String flowType = factorContext.getFlowTypeName();
        Integer requiredCount = mfaPolicyProvider.getRequiredFactorCount(userId, flowType);

        if (requiredCount == null) {
            requiredCount = 1; // 기본값
        }

        return factorContext.getCompletedFactors().size() >= requiredCount;
    }

    /**
     * 추가 팩터가 필요한지 확인
     */
    public boolean needsAdditionalFactors(FactorContext factorContext) {
        return factorContext.isMfaRequiredAsPerPolicy() &&
                !allRequiredFactorsCompleted(factorContext);
    }
}