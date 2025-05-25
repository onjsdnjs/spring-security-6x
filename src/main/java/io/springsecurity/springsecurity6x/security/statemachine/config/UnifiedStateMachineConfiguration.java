package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.config.redis.UnifiedRedisConfiguration;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.core.*;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.listener.MfaStateChangeListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

/**
 * 통합 State Machine 설정
 * - 모든 State Machine 관련 설정을 하나로 통합
 * - 중복 제거 및 명확한 의존성 관리
 */
@Slf4j
@Configuration
@Import(UnifiedRedisConfiguration.class)
@EnableConfigurationProperties({StateMachineProperties.class, AuthContextProperties.class})
@RequiredArgsConstructor
public class UnifiedStateMachineConfiguration {

    private final StateMachineProperties properties;
    private final AuthContextProperties authContextProperties;

    /**
     * State Machine 영속화 전략
     */
    @Bean
    @Primary
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist(
            @Value("${security.statemachine.persistence.type:memory}") String persistenceType,
            @Qualifier("stateMachinePersistRedisTemplate") RedisTemplate<String, byte[]> redisTemplate) {

        log.info("Configuring State Machine persistence with type: {}", persistenceType);

        switch (persistenceType.toLowerCase()) {
            case "redis":
                // Fallback 설정
                StateMachinePersist<MfaState, MfaEvent, String> fallback = null;
                if (properties.getPersistence() != null && properties.getPersistence().isEnableFallback()) {
                    fallback = new InMemoryStateMachinePersist();
                }

                int ttlMinutes = properties.getPersistence() != null && properties.getPersistence().getTtlMinutes() != null
                        ? properties.getPersistence().getTtlMinutes() : 30;

                // RedisTemplate<String, String>으로 변환 필요
                @SuppressWarnings("unchecked")
                RedisTemplate<String, String> stringRedisTemplate = (RedisTemplate<String, String>) (RedisTemplate<?, ?>) redisTemplate;

                return new ResilientRedisStateMachinePersist(
                        stringRedisTemplate,
                        fallback,
                        ttlMinutes
                );

            case "memory":
            default:
                return new InMemoryStateMachinePersist();
        }
    }

    /**
     * State Machine Persister
     */
    @Bean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist) {
        return new DefaultStateMachinePersister<>(stateMachinePersist);
    }

    /**
     * 분산 락 서비스
     * - RedisDistributedLockService를 사용
     * - Bean 이름을 명확히 지정하여 충돌 방지
     */
    @Bean(name = "RedisDistributedLockService")
    @Primary
    @ConditionalOnMissingBean(RedisDistributedLockService.class)
    public RedisDistributedLockService RedisDistributedLockService(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {
        log.info("Creating practical distributed lock service");
        return new RedisDistributedLockService(redisTemplate);
    }

    /**
     * MFA 이벤트 발행자
     */
    @Bean(name = "mfaEventPublisher")
    @Primary
    public MfaEventPublisher mfaEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        // Properties에서 events 설정 확인
        boolean eventsEnabled = properties.getEvents() != null && properties.getEvents().isEnabled();
        String eventType = properties.getEvents() != null ? properties.getEvents().getType() : "local";

        if (!eventsEnabled) {
            log.info("Event publishing disabled");
            return new NoOpEventPublisher();
        }

        log.info("Event publishing enabled with type: {}", eventType);

        switch (eventType.toLowerCase()) {
            case "redis":
                return new RedisBasedEventPublisher(redisTemplate, applicationEventPublisher);
            case "local":
            default:
                return new MfaEventPublisherImpl(applicationEventPublisher);
        }
    }

    /**
     * MFA State Machine Service
     */
    @Bean
    @Primary
    public MfaStateMachineService mfaStateMachineService(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            FactorContextStateAdapter factorContextAdapter,
            ContextPersistence contextPersistence,
            @Qualifier("mfaEventPublisher") MfaEventPublisher eventPublisher,
            @Qualifier("RedisDistributedLockService") RedisDistributedLockService lockService,
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        return new ScalableMfaStateMachineService(
                stateMachineFactory,
                stateMachinePersister,
                factorContextAdapter,
                contextPersistence,
                eventPublisher,
                lockService,
                redisTemplate
        );
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
     * Properties에 persistence와 events 설정 추가 필요
     */
    @Bean
    @ConditionalOnMissingBean
    public StateMachineProperties.PersistenceProperties persistenceProperties() {
        StateMachineProperties.PersistenceProperties props = new StateMachineProperties.PersistenceProperties();
        props.setType("memory");
        props.setEnableFallback(true);
        props.setTtlMinutes(30);
        return props;
    }

    @Bean
    @ConditionalOnMissingBean
    public StateMachineProperties.EventsProperties eventsProperties() {
        StateMachineProperties.EventsProperties props = new StateMachineProperties.EventsProperties();
        props.setEnabled(true);
        props.setType("local");
        return props;
    }

    @Bean
    @ConditionalOnMissingBean
    public StateMachineProperties.CacheProperties cacheProperties() {
        StateMachineProperties.CacheProperties props = new StateMachineProperties.CacheProperties();
        props.setMaxSize(1000);
        props.setTtlMinutes(5);
        return props;
    }

    /**
     * No-Op 이벤트 발행자
     */
    private static class NoOpEventPublisher implements MfaEventPublisher {
        @Override
        public void publishStateChange(String sessionId, MfaState state, MfaEvent event) {
            // Do nothing
        }

        @Override
        public void publishError(String sessionId, Exception error) {
            // Do nothing
        }

        @Override
        public void publishCustomEvent(String eventType, Object payload) {
            // Do nothing
        }
    }

    /**
     * Redis 기반 이벤트 발행자
     */
    private static class RedisBasedEventPublisher extends MfaEventPublisherImpl {
        private final RedisTemplate<String, String> redisTemplate;

        public RedisBasedEventPublisher(RedisTemplate<String, String> redisTemplate,
                                        ApplicationEventPublisher applicationEventPublisher) {
            super(applicationEventPublisher);
            this.redisTemplate = redisTemplate;
        }

        @Override
        public void publishStateChange(String sessionId, MfaState state, MfaEvent event) {
            // 로컬 발행
            super.publishStateChange(sessionId, state, event);

            // Redis Pub/Sub
            try {
                String message = String.format("{\"sessionId\":\"%s\",\"state\":\"%s\",\"event\":\"%s\",\"timestamp\":%d}",
                        sessionId, state.name(), event.name(), System.currentTimeMillis());
                redisTemplate.convertAndSend("mfa:events:state-change", message);
            } catch (Exception e) {
                log.error("Failed to publish event to Redis", e);
            }
        }
    }
}