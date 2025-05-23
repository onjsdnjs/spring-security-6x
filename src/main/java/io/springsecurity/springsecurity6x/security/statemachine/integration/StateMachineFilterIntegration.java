package io.springsecurity.springsecurity6x.security.statemachine.integration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;

/**
 * Filter와 State Machine 간의 통합 인터페이스
 */
public interface StateMachineFilterIntegration {

    /**
     * 요청 처리 전 State Machine 상태 확인
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param context Factor 컨텍스트
     * @return 처리 계속 여부
     */
    boolean preProcess(HttpServletRequest request, HttpServletResponse response, FactorContext context);

    /**
     * 요청 처리 후 State Machine 업데이트
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param context Factor 컨텍스트
     * @param result 처리 결과
     */
    void postProcess(HttpServletRequest request, HttpServletResponse response, FactorContext context, Object result);
}


