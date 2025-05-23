package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;

/**
 * MFA State Machine 서비스 인터페이스
 */
public interface MfaStateMachineService {

    /**
     * 상태 머신 초기화
     */
    void initializeStateMachine(FactorContext context, HttpServletRequest request);

    /**
     * 이벤트 전송
     */
    boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request);

    /**
     * 현재 상태 조회
     */
    MfaState getCurrentState(String sessionId);

    /**
     * 상태 머신 해제
     */
    void releaseStateMachine(String sessionId);
}