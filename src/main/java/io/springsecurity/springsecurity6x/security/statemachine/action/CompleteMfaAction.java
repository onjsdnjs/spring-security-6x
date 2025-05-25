package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CompleteMfaAction extends AbstractMfaStateAction {

    public CompleteMfaAction(FactorContextStateAdapter factorContextAdapter,
                             StateContextHelper stateContextHelper) {
        super(factorContextAdapter, stateContextHelper);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Completing MFA for session: {}", sessionId);

        // 완료된 팩터 목록 로깅
        logCompletedFactors(factorContext);

        // MFA 완료 시간 설정
        factorContext.setAttribute("completedAt", LocalDateTime.now());

        // 상태를 완료로 변경
        factorContext.changeState(MfaState.MFA_SUCCESSFUL);

        // 추가 완료 처리 로직
        performCompletionTasks(factorContext);

        // 이벤트 메타데이터 추가
        updateEventMetadata(context);

        log.info("MFA successfully completed for session: {}", sessionId);
    }

    private void logCompletedFactors(FactorContext factorContext) {
        List<AuthenticationStepConfig> completedFactors = factorContext.getCompletedFactors();
        if (completedFactors != null && !completedFactors.isEmpty()) {
            String completedFactorTypes = completedFactors.stream()
                    .map(AuthenticationStepConfig::getType)
                    .collect(Collectors.joining(", "));
            log.info("MFA completed with factors: {} for session: {}",
                    completedFactorTypes, factorContext.getMfaSessionId());
        }
    }

    private void performCompletionTasks(FactorContext factorContext) {
        // 감사 로그 기록을 위한 준비
        factorContext.setAttribute("completionTimestamp", System.currentTimeMillis());

        // 완료된 팩터들의 상세 정보 저장
        if (factorContext.getCompletedFactors() != null) {
            factorContext.setAttribute("totalFactorsCompleted",
                    factorContext.getCompletedFactors().size());
        }

        // 세션 지속 시간 계산
        long createdAt = factorContext.getCreatedAt();
        long durationSeconds = (System.currentTimeMillis() - createdAt) / 1000;
        factorContext.setAttribute("mfaDurationSeconds", durationSeconds);
    }

    private void updateEventMetadata(StateContext<MfaState, MfaEvent> context) {
        context.getExtendedState().getVariables().put("mfaCompletedAt", LocalDateTime.now());
        context.getExtendedState().getVariables().put("completionStatus", "SUCCESS");
    }

    @Override
    protected boolean canExecute(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        // MFA가 이미 완료된 경우 실행하지 않음
        if (MfaState.MFA_SUCCESSFUL.equals(factorContext.getCurrentState())) {
            log.warn("MFA already completed for session: {}", factorContext.getMfaSessionId());
            return false;
        }

        // 완료된 팩터가 없는 경우 실행하지 않음
        if (factorContext.getCompletedFactors() == null ||
                factorContext.getCompletedFactors().isEmpty()) {
            log.warn("No completed factors found for session: {}", factorContext.getMfaSessionId());
            return false;
        }

        return true;
    }
}