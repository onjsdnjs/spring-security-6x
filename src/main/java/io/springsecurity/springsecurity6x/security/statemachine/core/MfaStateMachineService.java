package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import org.springframework.statemachine.StateMachine;

/**
 * MFA State Machine 서비스의 메인 인터페이스
 * 기존 시스템과 State Machine 간의 Facade 역할
 */
public interface MfaStateMachineService {

    /**
     * 이벤트를 발생시켜 상태 전이를 트리거
     * @param sessionId MFA 세션 ID
     * @param event 발생시킬 이벤트
     * @param context 현재 Factor 컨텍스트
     * @return 전이 성공 여부
     */
    boolean sendEvent(String sessionId, MfaEvent event, FactorContext context);

    /**
     * 현재 상태 조회
     * @param sessionId MFA 세션 ID
     * @return 현재 MFA 상태
     */
    MfaState getCurrentState(String sessionId);

    /**
     * State Machine 인스턴스 조회 (고급 사용)
     * @param sessionId MFA 세션 ID
     * @return State Machine 인스턴스
     */
    StateMachine<MfaState, MfaEvent> getStateMachine(String sessionId);

    /**
     * State Machine 초기화/리셋
     * @param sessionId MFA 세션 ID
     * @param initialContext 초기 컨텍스트
     */
    void initializeStateMachine(String sessionId, FactorContext initialContext);

    /**
     * State Machine 제거
     * @param sessionId MFA 세션 ID
     */
    void releaseStateMachine(String sessionId);
}
