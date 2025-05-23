package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.action.Action;

import java.util.Map;

/**
 * MFA 상태 변경 액션의 추상 기본 클래스
 * 모든 MFA 관련 액션은 이 클래스를 상속받아 구현
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractMfaStateAction implements Action<MfaState, MfaEvent> {

    protected final FactorContextStateAdapter factorContextAdapter;
    protected final StateContextHelper stateContextHelper;

    @Override
    public final void execute(StateContext<MfaState, MfaEvent> context) {
        String sessionId = extractSessionId(context);
        log.debug("Executing action {} for session: {}", this.getClass().getSimpleName(), sessionId);

        try {
            // FactorContext 추출
            FactorContext factorContext = extractFactorContext(context);
            if (factorContext == null) {
                throw new IllegalStateException("FactorContext not found in state machine context");
            }

            // 액션별 구체적인 로직 실행
            doExecute(context, factorContext);

            // 변경된 FactorContext를 다시 상태 머신에 반영
            updateStateMachineVariables(context, factorContext);

            log.debug("Action {} completed successfully for session: {}",
                    this.getClass().getSimpleName(), sessionId);

        } catch (Exception e) {
            log.error("Error executing action {} for session: {}",
                    this.getClass().getSimpleName(), sessionId, e);
            handleError(context, e);
        }
    }

    /**
     * 각 액션의 구체적인 비즈니스 로직을 구현
     */
    protected abstract void doExecute(StateContext<MfaState, MfaEvent> context,
                                      FactorContext factorContext) throws Exception;

    /**
     * StateContext에서 세션 ID 추출
     */
    protected String extractSessionId(StateContext<MfaState, MfaEvent> context) {
        String sessionId = (String) context.getMessageHeader("mfaSessionId");
        if (sessionId == null) {
            sessionId = (String) context.getExtendedState().getVariables().get("mfaSessionId");
        }
        return sessionId;
    }

    /**
     * StateContext에서 FactorContext 추출
     * StateContextHelper를 사용하여 안전하게 추출
     */
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return stateContextHelper.extractFactorContext(context);
    }

    /**
     * 변경된 FactorContext를 StateContext에 업데이트
     */
    protected void updateStateMachineVariables(StateContext<MfaState, MfaEvent> context,
                                               FactorContext factorContext) {
        // FactorContextStateAdapter의 toStateMachineVariables 메서드 사용
        Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(factorContext);
        context.getExtendedState().getVariables().putAll(variables);
    }

    /**
     * 에러 처리 로직
     * 기본적으로 RuntimeException 으로 래핑하되, 구체적인 에러 타입에 따라 처리
     */
    protected void handleError(StateContext<MfaState, MfaEvent> context, Exception e) {
        if (e instanceof IllegalStateException || e instanceof IllegalArgumentException) {
            // 비즈니스 로직 에러는 그대로 전파
            throw (RuntimeException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else {
            // Checked exception은 RuntimeException 으로 래핑
            throw new RuntimeException("Error executing MFA action", e);
        }
    }

    /**
     * 액션 실행 전 검증 로직 (선택적 구현)
     */
    protected boolean canExecute(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        return true;
    }
}