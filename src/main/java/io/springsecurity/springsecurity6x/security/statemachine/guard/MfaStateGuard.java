package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import org.springframework.statemachine.guard.Guard;

/**
 * MFA State Machine Guard의 기본 인터페이스
 */
public interface MfaStateGuard extends Guard<MfaState, MfaEvent> {

    /**
     * Guard 이름 (로깅 및 모니터링용)
     * @return Guard 이름
     */
    String getGuardName();

    /**
     * Guard 실패 시 이유
     * @return 실패 이유 메시지
     */
    default String getFailureReason() {
        return "Guard condition not met: " + getGuardName();
    }
}

