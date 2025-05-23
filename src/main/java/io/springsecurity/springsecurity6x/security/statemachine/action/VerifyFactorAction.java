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

/**
 * 팩터 검증 액션
 * 선택된 팩터의 검증이 성공했을 때 실행
 */
@Slf4j
@Component
public class VerifyFactorAction extends AbstractMfaStateAction {

    public VerifyFactorAction(FactorContextStateAdapter factorContextAdapter,
                              StateContextHelper stateContextHelper) {
        super(factorContextAdapter, stateContextHelper);
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        String currentStepId = factorContext.getCurrentStepId();

        // currentStepId 검증
        if (currentStepId == null || currentStepId.isEmpty()) {
            throw new IllegalStateException(
                    "Cannot verify factor: currentStepId is null or empty for session: " + sessionId);
        }

        log.info("Verifying factor for step: {} in session: {}", currentStepId, sessionId);

        // 현재 팩터 타입 가져오기
        String factorType = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (factorType == null) {
            factorType = extractFactorTypeFromContext(context);
        }

        // 검증 완료된 팩터를 completedFactors에 추가
        AuthenticationStepConfig completedStep = createCompletedStep(
                currentStepId,
                factorType,
                factorContext
        );

        factorContext.getCompletedFactors().add(completedStep);

        // 검증 성공 정보 업데이트
        updateVerificationSuccess(factorContext, completedStep);

        // 재시도 횟수 초기화
        factorContext.setRetryCount(0);

        // 상태 업데이트
        factorContext.changeState(MfaState.FACTOR_VERIFICATION_COMPLETED);

        log.info("Factor {} verified successfully for session: {}", factorType, sessionId);
    }

    /**
     * 완료된 인증 단계 설정 생성
     */
    private AuthenticationStepConfig createCompletedStep(String stepId,
                                                         String factorType,
                                                         FactorContext factorContext) {
        AuthenticationStepConfig config = new AuthenticationStepConfig();
        config.setStepId(stepId);
        config.setType(factorType);
        config.setRequired(true);
        config.setOrder(factorContext.getCompletedFactors().size() + 1);

        // flowTypeName 설정 - FactorContext에서 가져오기
        String flowTypeName = factorContext.getFlowTypeName();
        if (flowTypeName == null || flowTypeName.isEmpty()) {
            flowTypeName = "mfa"; // 기본값
            log.warn("flowTypeName is null, using default: 'mfa'");
        }
        config.setType(flowTypeName);

        return config;
    }

    /**
     * 검증 성공 정보 업데이트
     */
    private void updateVerificationSuccess(FactorContext factorContext,
                                           AuthenticationStepConfig completedStep) {
        // 검증 시간 기록
        factorContext.setAttribute(
                "lastVerificationTime_" + completedStep.getType(),
                LocalDateTime.now().toString()
        );

        // 검증 성공 카운트 증가
        Integer successCount = (Integer) factorContext.getAttribute("verificationSuccessCount");
        if (successCount == null) {
            successCount = 0;
        }
        factorContext.setAttribute("verificationSuccessCount", successCount + 1);

        // 현재 단계 완료 처리
        factorContext.setCurrentStepId(null);
        factorContext.setCurrentProcessingFactor(null);
    }

    /**
     * Context에서 팩터 타입 추출 (fallback)
     */
    private String extractFactorTypeFromContext(StateContext<MfaState, MfaEvent> context) {
        // 메시지 헤더에서 확인
        String factorType = (String) context.getMessageHeader("factorType");
        if (factorType != null) {
            return factorType;
        }

        // ExtendedState에서 확인
        factorType = (String) context.getExtendedState()
                .getVariables().get("currentFactorType");
        if (factorType != null) {
            return factorType;
        }

        // 이벤트 페이로드에서 확인
        Object payload = context.getMessage().getPayload();
        if (payload instanceof String) {
            return (String) payload;
        }

        throw new IllegalStateException("Cannot determine factor type from context");
    }

    @Override
    protected boolean canExecute(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        // 현재 검증 중인 팩터가 없으면 실행하지 않음
        if (factorContext.getCurrentStepId() == null) {
            log.warn("No factor is currently being verified for session: {}",
                    factorContext.getMfaSessionId());
            return false;
        }

        return true;
    }
}