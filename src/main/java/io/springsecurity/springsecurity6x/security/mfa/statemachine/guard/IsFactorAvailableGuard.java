package io.springsecurity.springsecurity6x.security.mfa.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaGuard;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Optional;

@Slf4j
@Component("isFactorAvailableGuard") // 빈 이름 명시
@RequiredArgsConstructor
public class IsFactorAvailableGuard implements MfaGuard {

    private final MfaPolicyProvider mfaPolicyProvider; // 사용자 등록 팩터 조회 등

    @Override
    public boolean evaluate(MfaProcessingContext context) {
        // 이 Guard는 특정 팩터(예: 이벤트 페이로드로 전달된 팩터 타입 또는 현재 처리 대상 팩터)가
        // 사용 가능한지 (사용자가 등록했고, 현재 플로우에서 허용되는지 등) 확인해야 함.
        // MfaProcessingContext의 payload나 factorContext.getCurrentProcessingFactor() 등을 활용.

        AuthType factorToEvaluate;
        String stepIdToEvaluate = null;

        if (context.getPayload() != null && context.getPayload().get("selectedFactorType") != null) {
            factorToEvaluate = context.getPayload().get("selectedFactorType", AuthType.class);
        } else if (context.getPayload() != null && context.getPayload().get("stepId") != null) {
            // 만약 stepId로 팩터를 식별해야 한다면
            stepIdToEvaluate = context.getPayload().get("stepId", String.class);
            String finalStepIdToEvaluate = stepIdToEvaluate; // 람다 내부에서 사용하기 위해
            Optional<AuthenticationStepConfig> stepOpt = context.getFlowConfig().getStepConfigs().stream()
                    .filter(s -> finalStepIdToEvaluate.equals(s.getStepId()))
                    .findFirst();
            if (stepOpt.isEmpty()) {
                log.warn("IsFactorAvailableGuard: StepId '{}' not found in current flow config. Assuming factor not available.", stepIdToEvaluate);
                return false;
            }
            factorToEvaluate = stepOpt.get().getAuthType();
        }
        else {
            factorToEvaluate = context.getFactorContext().getCurrentProcessingFactor();
        }

        if (factorToEvaluate == null) {
            log.warn("IsFactorAvailableGuard: No factor to evaluate in context for user: {}", context.getFactorContext().getUsername());
            return false; // 평가할 팩터 정보가 없음
        }

        // 1. 사용자가 해당 팩터 타입을 등록했는지 확인
        List<AuthType> userRegisteredFactors = mfaPolicyProvider.getRegisteredMfaFactorsForUser(
                context.getFactorContext().getUsername()
                // , context.getFlowConfig() // MfaPolicyProvider.getRegisteredMfaFactorsForUser가 flowConfig도 받는다면 전달
        );

        if (CollectionUtils.isEmpty(userRegisteredFactors) || !userRegisteredFactors.contains(factorToEvaluate)) {
            log.debug("IsFactorAvailableGuard for user '{}': Factor {} is not registered by the user. Result: false",
                    context.getFactorContext().getUsername(), factorToEvaluate);
            return false;
        }

        // 2. 현재 MFA 플로우 설정에서 해당 팩터 타입이 허용되는지 확인 (stepId로 특정 step을 지정한 경우 해당 step만 확인)
        boolean allowedInFlow;
        if (stepIdToEvaluate != null) {
            String finalStepIdToEvaluate = stepIdToEvaluate;
            allowedInFlow = context.getFlowConfig().getStepConfigs().stream()
                    .anyMatch(step -> finalStepIdToEvaluate.equals(step.getStepId()) && step.getAuthType() == factorToEvaluate && step.isEnabled());
        } else {
            allowedInFlow = context.getFlowConfig().getStepConfigs().stream()
                    .anyMatch(step -> step.getAuthType() == factorToEvaluate && step.isRequired());
        }


        if (!allowedInFlow) {
            log.debug("IsFactorAvailableGuard for user '{}': Factor {} (StepId: {}) is not allowed or not enabled in the current flow config. Result: false",
                    context.getFactorContext().getUsername(), factorToEvaluate, stepIdToEvaluate);
            return false;
        }

        log.debug("IsFactorAvailableGuard for user '{}': Factor {} (StepId: {}) is available. Result: true",
                context.getFactorContext().getUsername(), factorToEvaluate, stepIdToEvaluate);
        return true;
    }
}