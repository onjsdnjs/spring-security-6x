package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.statemachine.core.InMemoryStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

/**
 * In-Memory 영속화 설정
 */
@Slf4j
@Configuration
@ConditionalOnProperty(prefix = "security.statemachine.redis", name = "enabled", havingValue = "false", matchIfMissing = true)
public class InMemoryPersistenceConfig {

    @Bean
    @Primary
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist() {
        log.info("Configuring In-Memory State Machine Persistence");
        return new InMemoryStateMachinePersist();
    }

    @Bean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist) {
        return new DefaultStateMachinePersister<>(stateMachinePersist);
    }
}