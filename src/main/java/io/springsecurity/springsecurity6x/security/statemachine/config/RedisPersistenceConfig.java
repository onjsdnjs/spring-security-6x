package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.statemachine.core.RedisStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

/**
 * Redis 영속화 설정
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnClass(RedisTemplate.class)
@ConditionalOnProperty(
        prefix = "security.statemachine.redis",
        name = "enabled",
        havingValue = "true"
)
@EnableConfigurationProperties(StateMachineProperties.class)
public class RedisPersistenceConfig {

    private final StateMachineProperties properties;

    @Bean
    @Primary
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, byte[]> redisTemplate) {

        log.info("Configuring Redis State Machine Persistence");

        int ttlMinutes = properties.getRedis().getTtlMinutes() != null ?
                properties.getRedis().getTtlMinutes() : 30;

        return new RedisStateMachinePersist(redisTemplate, ttlMinutes);
    }

    @Bean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist) {
        return new DefaultStateMachinePersister<>(stateMachinePersist);
    }
}