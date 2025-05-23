package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class VerifyFactorAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        AuthType currentFactor = factorContext.getCurrentProcessingFactor();
        log.info("Factor {} verified successfully for session: {}",
                currentFactor, factorContext.getMfaSessionId());

        // 완료된 팩터 목록에 추가
        // completedFactors는 List<AuthenticationStepConfig> 타입
        // 현재 처리 중인 factor에 해당하는 AuthenticationStepConfig을 찾아서 추가해야 함

        // StateContext 에서 현재 step 정보 가져오기
        String currentStepId = factorContext.getCurrentStepId();
        if (currentStepId != null) {
            // AuthenticationStepConfig 생성 또는 조회
            AuthenticationStepConfig completedStep = new AuthenticationStepConfig(
                    factorContext.getFlowTypeName(),
                    currentFactor.name(),
                    factorContext.getLastCompletedFactorOrder() + 1
            );
            completedStep.setStepId(currentStepId);

            factorContext.addCompletedFactor(completedStep);
            log.info("Added completed factor: {} with stepId: {}", currentFactor, currentStepId);
        } else {
            log.warn("Cannot add completed factor - currentStepId is null");
        }

        // 재시도 카운트 리셋
        factorContext.setRetryCount(0);
        factorContext.setLastError(null);
    }

    @Override
    public String getActionName() {
        return "VerifyFactorAction";
    }
}