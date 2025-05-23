package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 모든 필수 팩터가 완료되었는지 확인하는 Guard
 */
@Slf4j
@Component
public class AllFactorsCompletedGuard extends AbstractMfaStateGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    public AllFactorsCompletedGuard(MfaPolicyProvider mfaPolicyProvider) {
        this.mfaPolicyProvider = mfaPolicyProvider;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();

        try {
            // 완료된 팩터 수
            int completedCount = factorContext.getCompletedFactors() != null ?
                    factorContext.getCompletedFactors().size() : 0;

            // 필요한 팩터 수 (정책에서 동적으로 가져오기)
            int requiredCount = getRequiredFactorCount(factorContext);

            log.debug("Session {}: completed factors={}, required factors={}",
                    sessionId, completedCount, requiredCount);

            // 모든 필수 팩터가 완료되었는지 확인
            boolean allCompleted = completedCount >= requiredCount;

            if (allCompleted) {
                log.info("All required factors completed for session: {}", sessionId);
            } else {
                log.debug("More factors required for session: {} ({}/{})",
                        sessionId, completedCount, requiredCount);
            }

            return allCompleted;

        } catch (Exception e) {
            log.error("Error evaluating all factors completed for session: {}", sessionId, e);
            return false;
        }
    }

    /**
     * MFA 정책에서 필요한 팩터 수 가져오기
     */
    private int getRequiredFactorCount(FactorContext factorContext) {
        try {
            // MfaPolicyProvider를 통해 사용자별 정책 확인
            String userId = factorContext.getPrimaryAuthentication().getName();
            String flowType = factorContext.getFlowTypeName();

            // 정책 조회
            Integer requiredFactors = mfaPolicyProvider.getRequiredFactorCount(userId, flowType);

            if (requiredFactors != null && requiredFactors > 0) {
                log.debug("Policy requires {} factors for user: {} in flow: {}",
                        requiredFactors, userId, flowType);
                return requiredFactors;
            }

            // 기본값: 플로우 타입에 따라 결정
            return getDefaultRequiredFactorCount(flowType);

        } catch (Exception e) {
            log.warn("Failed to get required factor count from policy, using default", e);
            return getDefaultRequiredFactorCount(factorContext.getFlowTypeName());
        }
    }

    /**
     * 플로우 타입별 기본 필수 팩터 수
     */
    private int getDefaultRequiredFactorCount(String flowType) {
        if (flowType == null) {
            return 1;
        }

        switch (flowType.toLowerCase()) {
            case "mfa":
                return 2; // 일반 MFA는 2개 팩터 필요
            case "mfa-stepup":
                return 1; // Step-up 인증은 1개 추가 팩터
            case "mfa-transactional":
                return 1; // 거래 인증은 1개 팩터
            default:
                return 1;
        }
    }

    @Override
    public String getFailureReason() {
        return "Not all required factors have been completed";
    }

    /**
     * 특정 팩터 타입이 완료되었는지 확인
     */
    public boolean isFactorTypeCompleted(FactorContext factorContext, String factorType) {
        if (factorContext.getCompletedFactors() == null || factorType == null) {
            return false;
        }

        return factorContext.getCompletedFactors().stream()
                .anyMatch(factor -> factorType.equalsIgnoreCase(factor.getType()));
    }

    /**
     * 추가 팩터가 필요한지 확인
     */
    public boolean needsMoreFactors(FactorContext factorContext) {
        return !doEvaluate(null, factorContext);
    }

    @Override
    public String getGuardName() {
        return "AllFactorsCompletedGuard";
    }
}