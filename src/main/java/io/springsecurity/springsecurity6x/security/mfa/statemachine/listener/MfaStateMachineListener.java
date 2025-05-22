package io.springsecurity.springsecurity6x.security.mfa.statemachine.listener;

import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaEventPayload;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.config.MfaStateMachineDefinition;
import org.springframework.lang.Nullable;

/**
 * MFA 상태 머신의 생명주기 이벤트에 대한 리스너 인터페이스.
 */
public interface MfaStateMachineListener {

    default void onPreStateChange(MfaProcessingContext context, MfaFlowState from, MfaFlowState to, MfaStateMachineDefinition definition) {}
    default void onPostStateChange(MfaProcessingContext context, MfaFlowState from, MfaFlowState to, MfaStateMachineDefinition definition) {}

    default void onPreEventProcessing(MfaProcessingContext context, MfaFlowEvent event, @Nullable MfaEventPayload payload, MfaStateMachineDefinition definition) {}
    default void onPostEventProcessing(MfaProcessingContext context, MfaFlowEvent event, @Nullable MfaEventPayload payload, MfaStateMachineDefinition definition, boolean eventAccepted) {}

    default void onTransition(MfaProcessingContext context, MfaStateMachineDefinition.Transition transition, MfaStateMachineDefinition definition) {}
    default void onActionExecuting(MfaProcessingContext context, MfaStateMachineDefinition.Transition transition, String actionName, MfaStateMachineDefinition definition) {}
    default void onActionExecuted(MfaProcessingContext context, MfaStateMachineDefinition.Transition transition, String actionName, MfaStateMachineDefinition definition) {}

    default void onGuardEvaluated(MfaProcessingContext context, MfaStateMachineDefinition.Transition transition, boolean guardResult, MfaStateMachineDefinition definition) {}

    default void onStateMachineError(MfaProcessingContext context, Exception exception, MfaStateMachineDefinition definition) {}

    // 기타 필요한 라이프사이클 이벤트 추가 가능
}