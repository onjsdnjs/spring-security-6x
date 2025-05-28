package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.config.redis.UnifiedRedisConfiguration;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.core.event.MfaEventPublisher;
import io.springsecurity.springsecurity6x.security.statemachine.core.lock.OptimisticLockManager;
import io.springsecurity.springsecurity6x.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.core.persist.ResilientRedisStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.core.pool.StateMachinePool;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineServiceImpl;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.listener.MfaStateChangeListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.TimeUnit;

/**
 * 통합 State Machine 설정 - 간소화 버전
 *
 * 삭제/수정 사항:
 * - stateMachineProperties() 메서드 삭제 (이미 @EnableConfigurationProperties로 등록됨)
 * - @ConditionalOnMissingBean 제거 (불필요)
 * - @Primary 중복 제거
 */
@Slf4j
@Configuration
@Import({UnifiedRedisConfiguration.class, AsyncEventConfiguration.class})
@EnableConfigurationProperties({StateMachineProperties.class, AuthContextProperties.class})
@RequiredArgsConstructor
public class UnifiedStateMachineConfiguration {

    private final StateMachineProperties properties;
    private final AuthContextProperties authContextProperties;

    /**
     * State Machine Pool 설정
     */
    @Bean
    public StateMachinePool stateMachinePool(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister) {

        // ✅ null 체크 추가
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
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        // ✅ properties에서 직접 읽기
        String persistenceType = properties.getPersistence() != null ?
                properties.getPersistence().getType() : "memory";

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
    public OptimisticLockManager optimisticLockManager() {
        log.info("Creating Optimistic Lock Manager");
        return new OptimisticLockManager();
    }

    /**
     * MFA 이벤트 발행자
     */
    @Bean
    public MfaEventPublisher mfaEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        log.info("Creating MFA Event Publisher");
        return new MfaEventPublisher(applicationEventPublisher);
    }

    /**
     * MFA State Machine Service
     */
    @Bean
    public MfaStateMachineService mfaStateMachineService(
            StateMachinePool stateMachinePool,
            FactorContextStateAdapter factorContextAdapter,
            MfaEventPublisher eventPublisher,
            RedisDistributedLockService distributedLockService,
            OptimisticLockManager optimisticLockManager) {

        log.info("Creating MFA State Machine Service");

        return new MfaStateMachineServiceImpl(
                stateMachinePool,
                factorContextAdapter,
                eventPublisher,
                distributedLockService,
                optimisticLockManager
        );
    }

    /**
     * State Change Listener (메트릭 수집용)
     */
    @Bean
    @ConditionalOnProperty(
            prefix = "spring.auth.mfa",  // ✅ security.statemachine.mfa에서 변경
            name = "metrics-enabled",     // ✅ enableMetrics에서 변경
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
    @Bean
    public RedisDistributedLockService redisDistributedLockService(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {
        log.info("Creating Redis Distributed Lock Service");
        return new RedisDistributedLockService(redisTemplate);
    }

}