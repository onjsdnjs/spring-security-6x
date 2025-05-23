package io.springsecurity.springsecurity6x.security.statemachine.integration;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaStateMachineService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Authentication Handler와 State Machine을 통합하는 Advice 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateMachineHandlerAdviceImpl implements StateMachineHandlerAdvice {

    private final MfaStateMachineService stateMachineService;

    @Override
    public boolean beforeHandle(String handlerName, FactorContext context) {
        if (context == null || context.getMfaSessionId() == null) {
            log.debug("No valid FactorContext for handler advice");
            return true;
        }

        try {
            MfaState currentState = stateMachineService.getCurrentState(context.getMfaSessionId());
            log.debug("Handler {} starting with State Machine state: {}", handlerName, currentState);

            // 현재 상태에서 해당 핸들러 실행이 가능한지 검증
            if (!isHandlerAllowedInState(handlerName, currentState)) {
                log.warn("Handler {} not allowed in current state: {}", handlerName, currentState);
                return false;
            }

            return true;

        } catch (Exception e) {
            log.error("Error in handler before advice: {}", e.getMessage(), e);
            return true; // 오류 시 계속 진행
        }
    }

    @Override
    public void afterHandle(String handlerName, FactorContext context, boolean success) {
        if (context == null || context.getMfaSessionId() == null) {
            return;
        }

        try {
            // 핸들러 실행 결과에 따라 이벤트 발생
            MfaEvent event = determineEventFromHandler(handlerName, success);

            if (event != null) {
                log.info("Handler {} completed with success={}, triggering event: {}",
                        handlerName, success, event);

                stateMachineService.sendEvent(context.getMfaSessionId(), event, context);
            }

        } catch (Exception e) {
            log.error("Error in handler after advice: {}", e.getMessage(), e);
        }
    }

    /**
     * 현재 상태에서 핸들러 실행이 허용되는지 확인
     */
    private boolean isHandlerAllowedInState(String handlerName, MfaState currentState) {
        // 핸들러별 허용 상태 매핑
        switch (handlerName) {
            case "MfaInitHandler":
                return currentState == MfaState.START_MFA ||
                        currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;

            case "MfaSelectHandler":
                return currentState == MfaState.AWAITING_FACTOR_SELECTION;

            case "MfaVerifyHandler":
                return currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                        currentState == MfaState.FACTOR_VERIFICATION_IN_PROGRESS;

            default:
                return true; // 알 수 없는 핸들러는 허용
        }
    }

    /**
     * 핸들러 실행 결과로부터 이벤트 결정
     */
    private MfaEvent determineEventFromHandler(String handlerName, boolean success) {
        if (!success) {
            // 실패 시 공통 이벤트
            return MfaEvent.FACTOR_VERIFICATION_FAILED;
        }

        // 성공 시 핸들러별 이벤트
        return switch (handlerName) {
            case "PrimaryAuthenticationSuccessHandler" -> MfaEvent.PRIMARY_AUTH_SUCCESS;
            case "MfaFactorProcessingSuccessHandler" -> MfaEvent.FACTOR_VERIFIED_SUCCESS;
            default -> null;
        };
    }
}