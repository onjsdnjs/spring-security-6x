package io.springsecurity.springsecurity6x.security.statemachine.integration;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaStateMachineService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * State Machine Handler Advice 구현체
 * 핸들러 실행 전후로 State Machine 과의 통합을 담당
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateMachineHandlerAdviceImpl implements StateMachineHandlerAdvice {

    private final MfaStateMachineService stateMachineService;

    // 핸들러별 허용 상태 매핑
    private static final Map<String, Set<MfaState>> HANDLER_ALLOWED_STATES = new HashMap<>();

    static {
        // MfaInitHandler가 허용되는 상태들
        HANDLER_ALLOWED_STATES.put("MfaInitHandler", Set.of(
                MfaState.START_MFA,
                MfaState.PRIMARY_AUTHENTICATION_SUCCESSFUL
        ));

        // MfaSelectHandler가 허용되는 상태들
        HANDLER_ALLOWED_STATES.put("MfaSelectHandler", Set.of(
                MfaState.AWAITING_FACTOR_SELECTION,
                MfaState.FACTOR_VERIFICATION_COMPLETED
        ));

        // MfaChallengeHandler가 허용되는 상태들
        HANDLER_ALLOWED_STATES.put("MfaChallengeHandler", Set.of(
                MfaState.FACTOR_SELECTED,
                MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION
        ));

        // MfaVerifyHandler가 허용되는 상태들
        HANDLER_ALLOWED_STATES.put("MfaVerifyHandler", Set.of(
                MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION,
                MfaState.FACTOR_VERIFICATION_PENDING
        ));
    }

    @Override
    public boolean beforeHandler(String handlerName, FactorContext context,
                                 HttpServletRequest request) {
        if (context == null) {
            log.warn("FactorContext is null for handler: {}", handlerName);
            return false;
        }

        String sessionId = context.getMfaSessionId();
        MfaState currentState = context.getCurrentState();

        log.debug("Before handler {} execution for session {} in state {}",
                handlerName, sessionId, currentState);

        // 핸들러가 현재 상태에서 실행 가능한지 확인
        if (!isHandlerAllowedInState(handlerName, currentState)) {
            log.warn("Handler {} not allowed in state {} for session {}",
                    handlerName, currentState, sessionId);
            return false;
        }

        return true;
    }

    @Override
    public void afterHandler(String handlerName, FactorContext context,
                             HttpServletRequest request, Object result) {
        if (context == null) {
            log.warn("FactorContext is null after handler: {}", handlerName);
            return;
        }

        String sessionId = context.getMfaSessionId();
        log.debug("After handler {} execution for session {} with result type: {}",
                handlerName, sessionId, result != null ? result.getClass().getSimpleName() : "null");

        // 핸들러 실행 결과에 따른 이벤트 결정
        MfaEvent event = determineEventFromHandler(handlerName, result, context);

        if (event != null) {
            log.info("Triggering event {} after handler {} for session {}",
                    event, handlerName, sessionId);

            boolean accepted = stateMachineService.sendEvent(event, context, request);

            if (!accepted) {
                log.warn("Event {} was not accepted in current state {} for session {}",
                        event, context.getCurrentState(), sessionId);
            }
        }
    }

    @Override
    public void onHandlerError(String handlerName, FactorContext context,
                               HttpServletRequest request, Exception error) {
        if (context == null) {
            log.error("Error in handler {} but FactorContext is null", handlerName, error);
            return;
        }

        String sessionId = context.getMfaSessionId();
        log.error("Error in handler {} for session {}", handlerName, sessionId, error);

        // 에러 타입에 따른 이벤트 결정
        MfaEvent errorEvent = determineErrorEvent(error);

        if (errorEvent != null) {
            boolean accepted = stateMachineService.sendEvent(errorEvent, context, request);

            if (!accepted) {
                log.warn("Error event {} was not accepted for session {}",
                        errorEvent, sessionId);
            }
        }

        // 에러 정보를 컨텍스트에 저장
        context.setLastError(error.getMessage());
        context.setAttribute("lastErrorTime", System.currentTimeMillis());
        context.setAttribute("lastErrorHandler", handlerName);
    }

    /**
     * 핸들러가 현재 상태에서 실행 가능한지 확인
     */
    private boolean isHandlerAllowedInState(String handlerName, MfaState currentState) {
        Set<MfaState> allowedStates = HANDLER_ALLOWED_STATES.get(handlerName);

        if (allowedStates == null) {
            log.debug("No state restrictions defined for handler: {}", handlerName);
            return true; // 제한이 없으면 허용
        }

        return allowedStates.contains(currentState);
    }

    /**
     * 핸들러 실행 결과에 따른 이벤트 결정
     */
    private MfaEvent determineEventFromHandler(String handlerName, Object result,
                                               FactorContext context) {
        if (result == null) {
            return null;
        }

        String resultType = result.getClass().getSimpleName();

        switch (handlerName) {
            case "MfaInitHandler":
                if (resultType.contains("Success")) {
                    return context.isMfaRequiredAsPerPolicy() ?
                            MfaEvent.MFA_REQUIRED_SELECT_FACTOR :
                            MfaEvent.MFA_NOT_REQUIRED;
                }
                break;

            case "MfaSelectHandler":
                if (resultType.contains("Success")) {
                    return MfaEvent.FACTOR_SELECTED;
                }
                break;

            case "MfaChallengeHandler":
                if (resultType.contains("Success")) {
                    return MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY;
                } else if (resultType.contains("Failure")) {
                    return MfaEvent.CHALLENGE_INITIATION_FAILED;
                }
                break;

            case "MfaVerifyHandler":
                if (resultType.contains("Success")) {
                    return MfaEvent.FACTOR_VERIFIED_SUCCESS;
                } else if (resultType.contains("Failure")) {
                    return MfaEvent.FACTOR_VERIFICATION_FAILED;
                }
                break;
        }

        return null;
    }

    /**
     * 에러에 따른 이벤트 결정
     */
    private MfaEvent determineErrorEvent(Exception error) {
        if (error instanceof IllegalStateException) {
            return MfaEvent.SYSTEM_ERROR;
        } else if (error.getMessage() != null &&
                error.getMessage().contains("timeout")) {
            return MfaEvent.SESSION_TIMEOUT;
        }

        return MfaEvent.SYSTEM_ERROR;
    }
}