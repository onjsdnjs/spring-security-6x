package io.springsecurity.springsecurity6x.security.utils;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class StateMachineResponseEnhancer {

    public void enhanceResponse(Map<String, Object> response, FactorContext factorContext) {
        if (factorContext == null) return;

        Map<String, Object> stateMachineInfo = new HashMap<>();
        stateMachineInfo.put("currentState", factorContext.getCurrentState().name());
        stateMachineInfo.put("sessionId", factorContext.getMfaSessionId());

        // 상태별 메타데이터
        Map<String, Object> metadata = new HashMap<>();
        MfaState currentState = factorContext.getCurrentState();

        switch (currentState) {
            case AWAITING_FACTOR_SELECTION:
                metadata.put("availableFactors", factorContext.getAvailableFactors());
                break;

            case FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION:
                metadata.put("currentFactor", factorContext.getCurrentProcessingFactor());
                metadata.put("attemptsRemaining",
                        3 - factorContext.getRetryCount()); // 예시
                break;

            case MFA_FAILED_TERMINAL:
                metadata.put("failureReason", factorContext.getLastError());
                break;

            default:
                // 기본 메타데이터
                break;
        }

        stateMachineInfo.put("stateMetadata", metadata);
        stateMachineInfo.put("isTerminal", currentState.isTerminal());

        response.put("stateMachine", stateMachineInfo);

        log.debug("Enhanced response with state machine info: {}", stateMachineInfo);
    }
}