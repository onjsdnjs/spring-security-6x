package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 팩터 검증 완료 후 다음 단계를 결정하는 액션
 * - 추가 팩터가 필요한지 확인
 * - 모든 팩터가 완료되었는지 확인
 * - 다음 처리할 팩터 설정
 */
@Slf4j
@Component
public class DetermineNextFactorAction extends AbstractMfaStateAction {

    private final MfaPolicyProvider mfaPolicyProvider;

    public DetermineNextFactorAction(FactorContextStateAdapter factorContextAdapter,
                                     StateContextHelper stateContextHelper,
                                     MfaPolicyProvider mfaPolicyProvider) {
        super(factorContextAdapter, stateContextHelper);
        this.mfaPolicyProvider = mfaPolicyProvider;
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        String username = factorContext.getUsername();

        log.info("Determining next factor for session: {}, user: {}", sessionId, username);

        // 현재까지 완료된 팩터 수 확인
        int completedFactorsCount = factorContext.getCompletedFactors().size();
        log.debug("Completed factors count: {} for session: {}", completedFactorsCount, sessionId);

        // 정책 제공자를 통해 다음 팩터 결정
        mfaPolicyProvider.determineNextFactorToProcess(factorContext);

        // 다음 팩터가 있는지 확인
        if (factorContext.getCurrentProcessingFactor() != null) {
            log.info("Next factor determined: {} for session: {}",
                    factorContext.getCurrentProcessingFactor(), sessionId);

            // 다음 팩터 처리를 위한 준비
            factorContext.clearCurrentFactorProcessingState();
            factorContext.setAttribute("nextFactorDeterminedAt", System.currentTimeMillis());

            // 상태 기계 변수에 다음 팩터 정보 저장
            context.getExtendedState().getVariables().put("nextFactor",
                    factorContext.getCurrentProcessingFactor().name());
            context.getExtendedState().getVariables().put("pendingFactorCount",
                    getPendingFactorCount(factorContext));

        } else {
            log.info("No more factors to process for session: {}. All required factors completed.", sessionId);

            // 모든 팩터 완료 마크
            factorContext.setAttribute("allFactorsCompletedAt", System.currentTimeMillis());
            factorContext.setAttribute("totalFactorsCompleted", completedFactorsCount);

            // 상태 기계 변수 업데이트
            context.getExtendedState().getVariables().put("allFactorsCompleted", true);
            context.getExtendedState().getVariables().put("completionTime", System.currentTimeMillis());
        }

        // 실행 시간 기록 (성능 모니터링용)
        long executionTime = System.currentTimeMillis() -
                (Long) context.getMessageHeaders().get("timestamp");
        factorContext.setAttribute("determineNextFactorExecutionTime", executionTime);

        // State Machine에 업데이트된 컨텍스트 저장
        updateStateMachineVariables(context, factorContext);

        log.debug("DetermineNextFactorAction completed in {}ms for session: {}",
                executionTime, sessionId);
    }

    /**
     * 남은 팩터 수 계산
     */
    private int getPendingFactorCount(FactorContext factorContext) {
        String username = factorContext.getUsername();
        String flowTypeName = factorContext.getFlowTypeName();

        int requiredCount = mfaPolicyProvider.getRequiredFactorCount(username, flowTypeName);
        int completedCount = factorContext.getCompletedFactors().size();

        return Math.max(0, requiredCount - completedCount);
    }

    public String getActionName() {
        return "DetermineNextFactorAction";
    }
}