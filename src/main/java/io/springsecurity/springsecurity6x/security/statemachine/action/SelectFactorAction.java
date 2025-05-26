package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 팩터 선택 액션
 * - FACTOR_SELECTED 이벤트 처리
 * - PolicyProvider가 결정한 팩터 정보를 FactorContext에 설정
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SelectFactorAction extends AbstractMfaStateAction {

    private final StateContextHelper stateContextHelper;

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context) {
        // 1. FactorContext 추출
        FactorContext factorContext = stateContextHelper.extractFactorContext(context);
        if (factorContext == null) {
            handleError(context, "NO_FACTOR_CONTEXT", "FactorContext not found");
            return;
        }

        try {
            // 2. PolicyProvider가 저장한 속성에서 다음 팩터 정보 가져오기
            AuthType nextFactorType = (AuthType) factorContext.getAttribute("nextFactorType");
            String nextStepId = (String) factorContext.getAttribute("nextStepId");
            Object factorOptions = factorContext.getAttribute("nextFactorOptions");

            if (nextFactorType == null || nextStepId == null) {
                handleError(context, "NO_FACTOR_INFO", "Next factor information not found");
                return;
            }

            log.info("Setting next factor for user {}: Type={}, StepId={}",
                    factorContext.getUsername(), nextFactorType, nextStepId);

            // 3. FactorContext에 팩터 정보 설정
            factorContext.setCurrentProcessingFactor(nextFactorType);
            factorContext.setCurrentStepId(nextStepId);
            if (factorOptions != null) {
                factorContext.setCurrentFactorOptions(factorOptions);
            }

            // 4. 상태는 State Machine이 자동으로 AWAITING_FACTOR_CHALLENGE_INITIATION으로 전환

            // 5. 재시도 횟수 초기화
            factorContext.setRetryCount(0);
            factorContext.setLastError(null);

            // 6. FactorContext 저장
            stateContextHelper.saveFactorContext(context, factorContext);

            log.debug("Factor selection completed for session: {}", factorContext.getMfaSessionId());

        } catch (Exception e) {
            log.error("Error during factor selection", e);
            factorContext.setLastError(e.getMessage());
            handleError(context, "FACTOR_SELECTION_ERROR", e.getMessage());
        }
    }

    private void handleError(StateContext<MfaState, MfaEvent> context, String errorCode, String message) {
        log.error("Factor selection error: {} - {}", errorCode, message);
        context.getStateMachine().setStateMachineError(new RuntimeException(message));
        context.getExtendedState().getVariables().put("errorCode", errorCode);
        context.getExtendedState().getVariables().put("errorMessage", message);
    }
}