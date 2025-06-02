package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.exception.MfaStateMachineExceptions;
import io.springsecurity.springsecurity6x.security.statemachine.exception.MfaStateMachineExceptions.*;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.action.Action;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public abstract class AbstractMfaStateAction implements Action<MfaState, MfaEvent> {

    protected final FactorContextStateAdapter factorContextAdapter;

    @Override
    public final void execute(StateContext<MfaState, MfaEvent> context) {
        String sessionId = extractSessionId(context);
        log.debug("Executing action {} for session: {}", this.getClass().getSimpleName(), sessionId);

        FactorContext factorContext = null;
        try {
            // FactorContext 추출
            factorContext = extractFactorContext(context);
            if (factorContext == null) {
                throw new IllegalStateException("FactorContext not found in state machine context");
            }

            // 전제조건 검증
            validatePreconditions(context, factorContext);

            // 액션별 구체적인 로직 실행
            doExecute(context, factorContext);

            // 변경된 FactorContext를 다시 상태 머신에 반영
            updateStateMachineVariables(context, factorContext);

            log.debug("Action {} completed successfully for session: {}",
                    this.getClass().getSimpleName(), sessionId);

        } catch (InvalidFactorException | ChallengeGenerationException |
                 FactorVerificationException | StateTransitionException e) {
            log.error("Business exception in action {} for session: {}: {}",
                    this.getClass().getSimpleName(), sessionId, e.getMessage());

            // 1. 에러 정보를 컨텍스트에 저장
            factorContext.setLastError(e.getMessage());
            factorContext.setAttribute("lastErrorType", e.getClass().getSimpleName());
            factorContext.setAttribute("lastErrorTime", System.currentTimeMillis());

            // 2. State Machine에 에러 상태 저장
            context.getExtendedState().getVariables().put("actionError", true);
            context.getExtendedState().getVariables().put("actionErrorMessage", e.getMessage());
            context.getExtendedState().getVariables().put("actionErrorType", e.getClass().getSimpleName());

            // 3. 에러 이벤트 전송
            handleBusinessException(context, factorContext, e);

            // 4. 중요: 예외를 다시 발생시켜 상위로 전파
            throw new MfaStateMachineExceptions.StateMachineActionException(
                    "MFA action failed: " + e.getMessage(), e);

        } catch (Exception e) {
            // 기타 예외도 동일하게 처리
            log.error("Unexpected exception in action", e);

            if (factorContext != null) {
                factorContext.setLastError("System error: " + e.getMessage());
                factorContext.changeState(MfaState.MFA_SYSTEM_ERROR);
            }

            // 예외 재발생
            throw new MfaStateMachineExceptions.StateMachineActionException(
                    "Unexpected error in MFA action", e);
        }
    }

    /**
     * 전제조건 검증
     */
    protected void validatePreconditions(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext) throws Exception {
        // 기본 구현은 아무것도 하지 않음
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * 각 액션의 구체적인 비즈니스 로직을 구현
     */
    protected abstract void doExecute(StateContext<MfaState, MfaEvent> context,
                                      FactorContext factorContext) throws Exception;

    /**
     * 비즈니스 예외 처리
     */
    protected void handleBusinessException(StateContext<MfaState, MfaEvent> context,
                                           FactorContext factorContext,
                                           RuntimeException e) {
        // 에러 정보 저장
        if (factorContext != null) {
            factorContext.setLastError(e.getMessage());
            factorContext.setAttribute("lastErrorType", e.getClass().getSimpleName());
            factorContext.setAttribute("lastErrorTime", System.currentTimeMillis());
        }

        // 예외 타입에 따른 처리
        if (e instanceof InvalidFactorException) {
            context.getStateMachine().sendEvent(MfaEvent.SYSTEM_ERROR);
        } else if (e instanceof ChallengeGenerationException) {
            context.getStateMachine().sendEvent(MfaEvent.CHALLENGE_INITIATION_FAILED);
        } else if (e instanceof FactorVerificationException) {
            context.getStateMachine().sendEvent(MfaEvent.FACTOR_VERIFICATION_FAILED);
        }
    }

    /**
     * 세션 만료 상태로 전이
     */
    protected void transitionToExpiredState(StateContext<MfaState, MfaEvent> context,
                                            FactorContext factorContext) {
        if (factorContext != null) {
            factorContext.changeState(MfaState.MFA_SESSION_EXPIRED);
        }
        context.getStateMachine().sendEvent(MfaEvent.SESSION_TIMEOUT);
    }

    /**
     * 예상치 못한 에러 처리
     */
    protected void handleUnexpectedError(StateContext<MfaState, MfaEvent> context,
                                         FactorContext factorContext,
                                         Exception e) {
        if (factorContext != null) {
            factorContext.setLastError("Unexpected error: " + e.getMessage());
            factorContext.changeState(MfaState.MFA_SYSTEM_ERROR);
        }

        // Dead Letter Queue로 전송할 수 있도록 이벤트 발행
        context.getExtendedState().getVariables().put("unexpectedError", e);
        context.getExtendedState().getVariables().put("errorTimestamp", System.currentTimeMillis());
    }

    /**
     * StateContext 에서 세션 ID 추출
     */
    protected String extractSessionId(StateContext<MfaState, MfaEvent> context) {
        String sessionId = StateContextHelper.getFactorContext(context).getMfaSessionId();
        if (sessionId == null) {
            sessionId = (String) context.getMessageHeader("mfaSessionId");
        }
        if (sessionId == null) {
            sessionId = (String) context.getExtendedState().getVariables().get("sessionId");
        }
        return sessionId;
    }

    /**
     * StateContext 에서 FactorContext 추출
     */
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return StateContextHelper.getFactorContext(context);
    }

    /**
     * 변경된 FactorContext를 StateContext에 업데이트
     */
    protected void updateStateMachineVariables(StateContext<MfaState, MfaEvent> context,
                                               FactorContext factorContext) {
        StateContextHelper.setFactorContext(context, factorContext);
    }
}