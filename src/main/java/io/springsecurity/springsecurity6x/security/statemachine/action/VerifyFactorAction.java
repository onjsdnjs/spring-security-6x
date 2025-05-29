package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Component
public class VerifyFactorAction extends AbstractMfaStateAction {

    private final ApplicationContext applicationContext; // ApplicationContext 주입

    public VerifyFactorAction(FactorContextStateAdapter factorContextAdapter,
                              StateContextHelper stateContextHelper,
                              ApplicationContext applicationContext) { // 생성자 수정
        super(factorContextAdapter, stateContextHelper);
        this.applicationContext = applicationContext; // 주입 받은 ApplicationContext 할당
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        String currentStepId = factorContext.getCurrentStepId();

        if (currentStepId == null || currentStepId.isEmpty()) {
            log.error("Cannot verify factor: currentStepId is null or empty for session: {}. Transitioning to SYSTEM_ERROR.", sessionId);
            factorContext.setLastError("currentStepId is missing during factor verification.");
            // 시스템 에러 이벤트를 보내거나 상태를 직접 변경 (상태 머신 설정에 따라 다름)
            // 여기서는 상태를 직접 변경하는 대신, 예외를 발생시켜 AbstractMfaStateAction의 에러 핸들링 로직을 타도록 유도 가능
            throw new IllegalStateException("currentStepId is null or empty for session: " + sessionId);
        }

        log.info("Verifying factor for step: {} in session: {}", currentStepId, sessionId);

        String factorType = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (factorType == null) {
            // currentStepId 로부터 factorType 추론 시도 (Robustness)
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            Optional<AuthenticationFlowConfig> flowConfigOpt = platformConfig.getFlows().stream()
                    .filter(f -> f.getTypeName().equalsIgnoreCase(factorContext.getFlowTypeName()))
                    .findFirst();
            if (flowConfigOpt.isPresent()) {
                Optional<AuthenticationStepConfig> stepConfOpt = flowConfigOpt.get().getStepConfigs().stream()
                        .filter(s -> currentStepId.equals(s.getStepId()))
                        .findFirst();
                if (stepConfOpt.isPresent()) {
                    factorType = stepConfOpt.get().getType();
                }
            }
            if (factorType == null) {
                log.error("Cannot determine factor type for verification. currentProcessingFactor is null and could not be derived from stepId {} in session {}", currentStepId, sessionId);
                throw new IllegalStateException("Factor type for verification cannot be determined. Session: " + sessionId + ", StepId: " + currentStepId);
            }
            log.warn("currentProcessingFactor was null for session {}, derived factorType {} from stepId {}", sessionId, factorType, currentStepId);
        }


        AuthenticationStepConfig completedStep = createCompletedStep(
                currentStepId,
                factorType, // 이제 factorType이 null이 아님을 보장 (위 로직)
                factorContext
        );

        factorContext.addCompletedFactor(completedStep); // addCompletedFactor는 내부적으로 버전 증가
        updateVerificationSuccess(factorContext, completedStep);
        factorContext.setRetryCount(0); // 해당 팩터에 대한 재시도 횟수 초기화
        // factorContext.changeState(MfaState.FACTOR_VERIFICATION_COMPLETED); // 상태 변경은 StateMachine의 Transition에 의해 이루어짐

        log.info("Factor {} (StepId: {}) verified successfully for session: {}", factorType, currentStepId, sessionId);
    }

    private AuthenticationStepConfig createCompletedStep(String stepId,
                                                         String factorType,
                                                         FactorContext factorContext) {
        PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
        AuthenticationFlowConfig currentFlow = platformConfig.getFlows().stream()
                .filter(f -> f.getTypeName().equalsIgnoreCase(factorContext.getFlowTypeName()))
                .findFirst()
                .orElse(null);

        AuthenticationStepConfig originalStepConfig = null;
        if (currentFlow != null) {
            originalStepConfig = currentFlow.getStepConfigs().stream()
                    .filter(s -> stepId.equals(s.getStepId()))
                    .findFirst()
                    .orElse(null);
        }

        if (originalStepConfig == null) {
            log.warn("Original AuthenticationStepConfig not found for stepId '{}' in flow '{}'. Creating a default completed step. Session: {}",
                    stepId, factorContext.getFlowTypeName(), factorContext.getMfaSessionId());
            AuthenticationStepConfig fallbackStep = new AuthenticationStepConfig();
            fallbackStep.setStepId(stepId);
            fallbackStep.setType(factorType); // Ensure factorType is not null here
            fallbackStep.setOrder(factorContext.getCompletedFactors().size() + 1); // Approximate order
            fallbackStep.setRequired(true); // Default to required
            return fallbackStep;
        }

        // Create a new config for the completed step, copying relevant properties
        AuthenticationStepConfig completed = new AuthenticationStepConfig();
        completed.setStepId(originalStepConfig.getStepId());
        completed.setType(originalStepConfig.getType()); // Use type from original config
        completed.setOrder(originalStepConfig.getOrder());
        completed.setRequired(originalStepConfig.isRequired());
        // Options are generally not needed for the "completed" record itself
        // but if required for audit or other reasons, they could be selectively copied.
        // Be cautious about copying mutable options directly.
        return completed;
    }

    private void updateVerificationSuccess(FactorContext factorContext,
                                           AuthenticationStepConfig completedStep) {
        factorContext.setAttribute(
                "lastVerificationTime_" + completedStep.getStepId(), // stepId를 사용해 더 고유하게
                LocalDateTime.now().toString()
        );

        Integer successCount = (Integer) factorContext.getAttribute("verificationSuccessCount");
        factorContext.setAttribute("verificationSuccessCount", (successCount == null ? 0 : successCount) + 1);

        // 현재 처리 중인 팩터 정보 초기화는 MfaPolicyProvider.determineNextFactorToProcess 또는 관련 액션에서 수행
        // factorContext.setCurrentStepId(null); // 여기서 초기화하면 다음 로직에 영향
        // factorContext.setCurrentProcessingFactor(null);
    }


    // extractFactorTypeFromContext 메서드는 이제 factorType이 null일 경우를 대비한
    // doExecute 내부 로직으로 통합되어 불필요해질 수 있습니다.
    // 만약 계속 사용한다면, currentProcessingFactor가 null일 때의 방어 로직이 필요합니다.
    private String extractFactorTypeFromContext(StateContext<MfaState, MfaEvent> context) {
        // This method might be redundant if factorContext.getCurrentProcessingFactor() is reliable.
        // It was a fallback. If getCurrentProcessingFactor() can be null and needs deriving,
        // then this logic (or similar) is needed.
        Object factorTypeHeader = context.getMessageHeader("selectedFactorType"); // Or a similar header
        if (factorTypeHeader instanceof String) {
            return (String) factorTypeHeader;
        }
        Object factorTypeVar = context.getExtendedState().getVariables().get("currentFactorType"); // Assuming this variable exists
        if (factorTypeVar instanceof String) {
            return (String) factorTypeVar;
        }
        // If currentProcessingFactor is reliable, this could be:
        // FactorContext fc = stateContextHelper.extractFactorContext(context);
        // if (fc != null && fc.getCurrentProcessingFactor() != null) return fc.getCurrentProcessingFactor().name();

        log.error("Cannot determine factor type from context for session: {}", extractSessionId(context));
        throw new IllegalStateException("Cannot determine factor type from context");
    }

}