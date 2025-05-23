package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.core.*;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.*;
import io.springsecurity.springsecurity6x.security.statemachine.action.*;
import io.springsecurity.springsecurity6x.security.statemachine.guard.*;
import io.springsecurity.springsecurity6x.security.statemachine.integration.*;
import io.springsecurity.springsecurity6x.security.statemachine.listener.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.service.DefaultStateMachineService;
import org.springframework.statemachine.service.StateMachineService;

/**
 * State Machine 자동 설정
 */
@Configuration
@EnableConfigurationProperties(StateMachineProperties.class)
@ComponentScan(basePackages = "io.springsecurity.springsecurity6x.security.statemachine")
@Import({MfaStateMachineConfiguration.class})
public class StateMachineAutoConfiguration {

    @Bean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist) {
        return new DefaultStateMachinePersister<>(stateMachinePersist);
    }

    @Bean
    @ConditionalOnProperty(
            prefix = "security.statemachine.mfa",
            name = "enableMetrics",
            havingValue = "true",
            matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        return new MfaStateChangeListener();
    }

    @Bean
    public MfaStateMachineConfigurer mfaStateMachineConfigurer(MfaStateMachineService stateMachineService) {
        return new MfaStateMachineConfigurer(stateMachineService);
    }
}