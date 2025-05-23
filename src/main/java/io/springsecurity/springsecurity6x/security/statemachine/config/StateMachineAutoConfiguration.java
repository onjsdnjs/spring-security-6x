package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.listener.MfaStateChangeListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * State Machine 자동 구성
 * In-Memory 및 Redis 기반 영속화 지원
 */
@Slf4j
@Configuration
@EnableConfigurationProperties({StateMachineProperties.class, AuthContextProperties.class})
@RequiredArgsConstructor
public class StateMachineAutoConfiguration {

    private final StateMachineProperties properties;
    private final AuthContextProperties authContextProperties;

    /**
     * State Change Listener (메트릭 수집용)
     */
    @Bean
    @ConditionalOnProperty(prefix = "security.statemachine.mfa", name = "enableMetrics", havingValue = "true", matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        log.info("Enabling MFA State Change Listener for metrics");
        return new MfaStateChangeListener();
    }
}