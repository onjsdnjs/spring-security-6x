package io.springsecurity.springsecurity6x.security.statemachine.integration;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;

/**
 * Handler와 State Machine 간의 통합을 위한 Advice
 */
public interface StateMachineHandlerAdvice {

    /**
     * Handler 실행 전 처리
     * @param handlerName Handler 이름
     * @param context Factor 컨텍스트
     * @return 실행 계속 여부
     */
    boolean beforeHandle(String handlerName, FactorContext context);

    /**
     * Handler 실행 후 처리
     * @param handlerName Handler 이름
     * @param context Factor 컨텍스트
     * @param success 성공 여부
     */
    void afterHandle(String handlerName, FactorContext context, boolean success);
}
