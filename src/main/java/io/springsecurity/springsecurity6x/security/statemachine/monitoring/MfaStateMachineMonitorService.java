package io.springsecurity.springsecurity6x.security.statemachine.monitoring;


import io.springsecurity.springsecurity6x.security.statemachine.core.event.MfaStateMachineEvents;
import org.springframework.boot.actuate.health.Health;

import java.util.Map;

/**
 * MFA State Machine 모니터링 서비스 인터페이스
 */
public interface MfaStateMachineMonitorService {

    void handleStateChange(MfaStateMachineEvents.StateChangeEvent event);

    void handleError(MfaStateMachineEvents.ErrorEvent event);

    Health health();

    Map<String, Double> identifyBottlenecks();
}