package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * MFA 초기화 액션
 * - PRIMARY_AUTH_SUCCESS 이벤트 처리
 * - MfaPolicyProvider 호출하여 MFA 필요 여부 평가
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class InitializeMfaAction extends AbstractMfaStateAction {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final StateContextHelper stateContextHelper;

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context) {
        // 1. FactorContext 추출
        FactorContext factorContext = stateContextHelper.extractFactorContext(context);
        if (factorContext == null) {
            handleError(context, "NO_FACTOR_CONTEXT", "FactorContext not found in StateContext");
            return;
        }

        // 2. Authentication 추출
        Authentication authentication = extractAuthentication(context);
        if (authentication == null) {
            handleError(context, "NO_AUTHENTICATION", "Authentication not found");
            return;
        }

        try {
            log.info("Initializing MFA for user: {}, sessionId: {}",
                    authentication.getName(), factorContext.getMfaSessionId());

            // 3. 상태를 START_MFA로 변경 (State Machine이 자동으로 처리)
            factorContext.changeState(MfaState.START_MFA);

            // 4. MFA 정책 평가 - PolicyProvider가 이벤트 전송하므로 여기서는 호출만
            mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, factorContext);

            // 5. FactorContext를 State Machine에 저장
            stateContextHelper.saveFactorContext(context, factorContext);

            log.debug("MFA initialization completed for session: {}", factorContext.getMfaSessionId());

        } catch (Exception e) {
            log.error("Error during MFA initialization", e);
            factorContext.setLastError(e.getMessage());
            handleError(context, "INITIALIZATION_ERROR", e.getMessage());
        }
    }

    private Authentication extractAuthentication(StateContext<MfaState, MfaEvent> context) {
        // 메시지 헤더에서 추출
        Object auth = context.getMessageHeader("authentication");
        if (auth instanceof Authentication) {
            return (Authentication) auth;
        }

        // ExtendedState에서 추출
        auth = context.getExtendedState().getVariables().get("primaryAuthentication");
        if (auth instanceof Authentication) {
            return (Authentication) auth;
        }

        return null;
    }

    private void handleError(StateContext<MfaState, MfaEvent> context, String errorCode, String message) {
        log.error("MFA initialization error: {} - {}", errorCode, message);
        context.getStateMachine().setStateMachineError(new RuntimeException(message));

        // 에러 정보를 ExtendedState에 저장
        context.getExtendedState().getVariables().put("errorCode", errorCode);
        context.getExtendedState().getVariables().put("errorMessage", message);
    }
}