package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaStateMachinePersisterImpl;
import io.springsecurity.springsecurity6x.security.statemachine.core.RedisStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.listener.MfaStateChangeListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.StateMachineConfigurerAdapter;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.EnumSet;

/**
 * State Machine 자동 구성
 * In-Memory 및 Redis 기반 영속화 지원
 */
@Slf4j
@Configuration
@EnableStateMachineFactory
@EnableConfigurationProperties({StateMachineProperties.class, AuthContextProperties.class})
@RequiredArgsConstructor
public class StateMachineAutoConfiguration {

    private final StateMachineProperties properties;
    private final AuthContextProperties authContextProperties;

    /**
     * State Machine Factory 빈 등록
     * @EnableStateMachineFactory가 자동으로 생성하는 팩토리를 사용
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaStateMachineConfiguration mfaStateMachineConfiguration() {
        return new MfaStateMachineConfiguration();
    }

    /**
     * In-Memory State Machine Persist (기본값)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "security.statemachine.redis",
            name = "enabled",
            havingValue = "false",
            matchIfMissing = true
    )
    public StateMachinePersist<MfaState, MfaEvent, String> inMemoryStateMachinePersist() {
        log.info("Configuring In-Memory State Machine Persistence");
        return new MfaStateMachinePersisterImpl();
    }

    /**
     * Redis State Machine Persist
     */
    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    @ConditionalOnProperty(
            prefix = "security.statemachine.redis",
            name = "enabled",
            havingValue = "true"
    )
    public StateMachinePersist<MfaState, MfaEvent, String> redisStateMachinePersist(
            RedisTemplate<String, byte[]> redisTemplate) {

        log.info("Configuring Redis State Machine Persistence");

        int ttlMinutes = properties.getRedis().getTtlMinutes() != null ?
                properties.getRedis().getTtlMinutes() : 30;

        return new RedisStateMachinePersist(redisTemplate, ttlMinutes);
    }

    /**
     * State Machine Persister
     */
    @Bean
    @ConditionalOnMissingBean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist) {

        return new DefaultStateMachinePersister<>(stateMachinePersist);
    }

    /**
     * State Change Listener (메트릭 수집용)
     */
    @Bean
    @ConditionalOnProperty(
            prefix = "security.statemachine.mfa",
            name = "enableMetrics",
            havingValue = "true",
            matchIfMissing = true
    )
    public MfaStateChangeListener mfaStateChangeListener() {
        log.info("Enabling MFA State Change Listener for metrics");
        return new MfaStateChangeListener();
    }

    /**
     * State Machine 기본 설정
     */
    @Configuration
    public static class DefaultStateMachineConfig
            extends StateMachineConfigurerAdapter<MfaState, MfaEvent> {

        @Override
        public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config)
                throws Exception {
            config
                    .withConfiguration()
                    .autoStartup(true)
                    .machineId("mfa-state-machine");
        }

        @Override
        public void configure(StateMachineStateConfigurer<MfaState, MfaEvent> states)
                throws Exception {
            states
                    .withStates()
                    .initial(MfaState.IDLE)
                    .states(EnumSet.allOf(MfaState.class))
                    .end(MfaState.MFA_SUCCESSFUL)
                    .end(MfaState.MFA_FAILED_TERMINAL)
                    .end(MfaState.MFA_CANCELLED)
                    .end(MfaState.MFA_SESSION_EXPIRED);
        }

        @Override
        public void configure(StateMachineTransitionConfigurer<MfaState, MfaEvent> transitions)
                throws Exception {
            // 기본 전이 규칙은 MfaStateMachineConfiguration에서 정의
        }
    }

    /**
     * Redis Template 빈 (Redis 사용 시 필요)
     * 실제 프로젝트에서는 별도의 Redis Configuration에서 정의
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "security.statemachine.redis",
            name = "enabled",
            havingValue = "true"
    )
    public RedisTemplate<String, byte[]> stateMachineRedisTemplate() {
        RedisTemplate<String, byte[]> template = new RedisTemplate<>();
        // Redis 연결 설정은 spring.redis.* 프로퍼티를 통해 자동 구성됨
        return template;
    }
}