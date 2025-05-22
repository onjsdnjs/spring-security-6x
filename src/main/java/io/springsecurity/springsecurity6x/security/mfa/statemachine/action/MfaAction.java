package io.springsecurity.springsecurity6x.security.mfa.statemachine.action;

import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import jakarta.servlet.ServletException;

import java.io.IOException;

/**
 * MFA 상태 머신에서 상태 전이 또는 상태 변경 시 수행될 액션을 정의하는 인터페이스입니다.
 */
@FunctionalInterface
public interface MfaAction {

    /**
     * 액션을 실행합니다.
     *
     * @param context 현재 MFA 처리 컨텍스트
     * @throws IOException Servlet I/O 예외 발생 가능
     * @throws ServletException Servlet 관련 예외 발생 가능
     *
     * 액션 실행 결과로 다음 이벤트를 발생시켜야 할 경우,
     * 이 메소드가 MfaFlowEvent를 반환하거나,
     * 또는 MfaProcessingContext를 통해 StateMachine에 접근하여 이벤트를 전송하도록 설계할 수 있습니다.
     * 여기서는 간단하게 void로 정의하고, 필요시 context를 통해 상태 머신에 접근한다고 가정합니다.
     */
    void execute(MfaProcessingContext context) throws IOException, ServletException;
}