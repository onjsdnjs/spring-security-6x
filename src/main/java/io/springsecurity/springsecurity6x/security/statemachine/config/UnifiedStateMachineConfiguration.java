package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.config.redis.UnifiedRedisConfiguration;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.core.InMemoryStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaEventPublisher;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.core.ResilientRedisStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.core.event.AsyncEventPublisher;
import io.springsecurity.springsecurity6x.security.statemachine.core.lock.OptimisticLockManager;
import io.springsecurity.springsecurity6x.security.statemachine.core.pool.StateMachinePool;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.OptimizedMfaStateMachineService;
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

import java.util.concurrent.TimeUnit;

/**
 * 통합 State Machine 설정
 * - 모든 State Machine 관련 설정을 하나로 통합
 * - 최적화된 구성 요소 사용
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
     * State Machine Pool 설정
     */
    @Bean
    @Primary
    public StateMachinePool stateMachinePool(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister) {

        int corePoolSize = properties.getPool() != null ? properties.getPool().getCoreSize() : 10;
        int maxPoolSize = properties.getPool() != null ? properties.getPool().getMaxSize() : 50;
        long keepAliveTime = properties.getPool() != null ? properties.getPool().getKeepAliveTime() : 10;

        log.info("Creating State Machine Pool - Core: {}, Max: {}, KeepAlive: {}min",
                corePoolSize, maxPoolSize, keepAliveTime);

        return new StateMachinePool(
                stateMachineFactory,
                stateMachinePersister,
                corePoolSize,
                maxPoolSize,
                keepAliveTime,
                TimeUnit.MINUTES
        );
    }

    /**
     * State Machine 영속화 전략
     */
    @Bean
    @Primary
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist(
            @Value("${security.statemachine.persistence.type:memory}") String persistenceType,
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        log.info("Configuring State Machine persistence with type: {}", persistenceType);

        switch (persistenceType.toLowerCase()) {
            case "redis":
                StateMachinePersist<MfaState, MfaEvent, String> fallback = null;
                if (properties.getPersistence() != null && properties.getPersistence().isEnableFallback()) {
                    fallback = new InMemoryStateMachinePersist();
                }

                int ttlMinutes = properties.getPersistence() != null && properties.getPersistence().getTtlMinutes() != null
                        ? properties.getPersistence().getTtlMinutes() : 30;

                return new ResilientRedisStateMachinePersist(redisTemplate, fallback, ttlMinutes);

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
     * Optimistic Lock 관리자
     */
    @Bean
    @Primary
    public OptimisticLockManager optimisticLockManager() {
        log.info("Creating Optimistic Lock Manager");
        return new OptimisticLockManager();
    }

    /**
     * 비동기 이벤트 발행자
     */
    @Bean
    @Primary
    public AsyncEventPublisher asyncEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        log.info("Creating Async Event Publisher");
        return new AsyncEventPublisher(applicationEventPublisher, redisTemplate);
    }

    /**
     * MFA 이벤트 발행자 (AsyncEventPublisher 사용)
     */
    @Bean(name = "mfaEventPublisher")
    public MfaEventPublisher mfaEventPublisher(AsyncEventPublisher asyncEventPublisher) {
        return asyncEventPublisher;
    }

    /**
     * 최적화된 MFA State Machine Service
     */
    @Bean
    @Primary
    public MfaStateMachineService mfaStateMachineService(
            StateMachinePool stateMachinePool,
            FactorContextStateAdapter factorContextAdapter,
            ContextPersistence contextPersistence,
            AsyncEventPublisher eventPublisher,
            DistributedLockManager distributedLockManager,
            OptimisticLockManager optimisticLockManager) {

        log.info("Creating Optimized MFA State Machine Service");

        return new OptimizedMfaStateMachineService(
                stateMachinePool,
                factorContextAdapter,
                contextPersistence,
                eventPublisher,
                distributedLockManager,
                optimisticLockManager
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
     * Redis Distributed Lock Service
     */
    @Bean(name = "RedisDistributedLockService")
    @Primary
    @ConditionalOnMissingBean(RedisDistributedLockService.class)
    public RedisDistributedLockService redisDistributedLockService(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {
        log.info("Creating Redis Distributed Lock Service");
        return new RedisDistributedLockService(redisTemplate);
    }

    /**
     * State Machine Properties 기본값 설정
     */
    @Bean
    @ConditionalOnMissingBean
    public StateMachineProperties stateMachineProperties() {
        StateMachineProperties props = new StateMachineProperties();

        // Pool 설정
        StateMachineProperties.PoolProperties poolProps = new StateMachineProperties.PoolProperties();
        poolProps.setCoreSize(10);
        poolProps.setMaxSize(50);
        poolProps.setKeepAliveTime(10L);
        props.setPool(poolProps);

        // Persistence 설정
        StateMachineProperties.PersistenceProperties persistenceProps = new StateMachineProperties.PersistenceProperties();
        persistenceProps.setType("memory");
        persistenceProps.setEnableFallback(true);
        persistenceProps.setTtlMinutes(30);
        props.setPersistence(persistenceProps);

        // Events 설정
        StateMachineProperties.EventsProperties eventsProps = new StateMachineProperties.EventsProperties();
        eventsProps.setEnabled(true);
        eventsProps.setType("local");
        props.setEvents(eventsProps);

        // MFA 설정
        StateMachineProperties.MfaProperties mfaProps = new StateMachineProperties.MfaProperties();
        mfaProps.setEnableMetrics(true);
        mfaProps.setMaxRetries(3);
        mfaProps.setSessionTimeoutMinutes(30);
        props.setMfa(mfaProps);

        return props;
    }
}