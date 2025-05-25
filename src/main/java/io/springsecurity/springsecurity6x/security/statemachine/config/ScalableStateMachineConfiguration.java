package io.springsecurity.springsecurity6x.security.statemachine.config;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.core.*;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

/**
 * 확장 가능한 State Machine 설정
 * - 환경별 설정 분리
 * - 조건부 Bean 생성
 * - 성능 최적화 옵션
 */
@Slf4j
@Configuration
@EnableConfigurationProperties(StateMachineProperties.class)
@RequiredArgsConstructor
public class ScalableStateMachineConfiguration {

    private final StateMachineProperties properties;

    /**
     * Redis Template 설정 (State Machine 전용)
     */
    @Bean(name = "stateMachineRedisTemplate")
    @ConditionalOnProperty(prefix = "security.statemachine", name = "persistence.type", havingValue = "redis")
    public RedisTemplate<String, String> stateMachineRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // String 직렬화 사용 (성능 최적화)
        StringRedisSerializer serializer = new StringRedisSerializer();
        template.setKeySerializer(serializer);
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(serializer);
        template.setHashValueSerializer(serializer);

        template.afterPropertiesSet();

        log.info("State Machine Redis template configured");
        return template;
    }

    /**
     * State Machine 영속화 전략 선택
     */
    @Bean
    @Primary
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist(
            @Value("${security.statemachine.persistence.type:memory}") String persistenceType,
            RedisConnectionFactory redisConnectionFactory) {

        log.info("Configuring State Machine persistence with type: {}", persistenceType);

        return switch (persistenceType.toLowerCase()) {
            case "redis" -> redisStateMachinePersist(redisConnectionFactory);
            case "hybrid" -> hybridStateMachinePersist(redisConnectionFactory);
            default -> inMemoryStateMachinePersist();
        };
    }

    /**
     * Redis 기반 영속화 (프로덕션)
     */
    private StateMachinePersist<MfaState, MfaEvent, String> redisStateMachinePersist(
            RedisConnectionFactory connectionFactory) {

        RedisTemplate<String, String> redisTemplate = stateMachineRedisTemplate(connectionFactory);

        // Fallback으로 In-Memory 사용
        StateMachinePersist<MfaState, MfaEvent, String> fallback =
                properties.getPersistence().isEnableFallback() ? inMemoryStateMachinePersist() : null;

        return new ResilientRedisStateMachinePersist(
                redisTemplate,
                fallback,
                properties.getPersistence().getTtlMinutes()
        );
    }

    /**
     * 하이브리드 영속화 (Redis + In-Memory 캐시)
     */
    private StateMachinePersist<MfaState, MfaEvent, String> hybridStateMachinePersist(
            RedisConnectionFactory connectionFactory) {

        StateMachinePersist<MfaState, MfaEvent, String> redisPersist =
                redisStateMachinePersist(connectionFactory);

        return new CachedStateMachinePersist(
                redisPersist,
                properties.getCache().getMaxSize(),
                properties.getCache().getTtlMinutes()
        );
    }

    /**
     * In-Memory 영속화 (개발/테스트)
     */
    private StateMachinePersist<MfaState, MfaEvent, String> inMemoryStateMachinePersist() {
        return new InMemoryStateMachinePersist();
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
     * MFA State Machine Service (확장 가능한 구현)
     */
    @Bean
    @Primary
    public MfaStateMachineService mfaStateMachineService(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            FactorContextStateAdapter factorContextAdapter,
            ContextPersistence contextPersistence,
            @Qualifier("mfaEventPublisher") MfaEventPublisher eventPublisher,
            @Qualifier("RedisDistributedLockService") RedisDistributedLockService lockService,  // 추가
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        return new ScalableMfaStateMachineService(
                stateMachineFactory,
                stateMachinePersister,
                factorContextAdapter,
                contextPersistence,
                eventPublisher,
                lockService,  // 누락된 파라미터 추가
                redisTemplate
        );
    }

    /**
     * 분산 락 서비스
     */
    @Bean(name = "RedisDistributedLockService")  // Bean 이름 명시
    @Primary
    @ConditionalOnProperty(prefix = "security.statemachine", name = "distributed-lock.enabled",
            havingValue = "true", matchIfMissing = true)
    public RedisDistributedLockService RedisDistributedLockService(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {
        log.info("Distributed lock service enabled");
        return new RedisDistributedLockService(redisTemplate);
    }

    /**
     * 이벤트 발행자
     */
    @Bean(name = "mfaEventPublisher")
    @Primary
    public MfaEventPublisher mfaEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            @Autowired(required = false) @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        if (properties.getEvents().isEnabled()) {
            log.info("Event publishing enabled with type: {}", properties.getEvents().getType());

            switch (properties.getEvents().getType()) {
                case "redis":
                    if (redisTemplate == null) {
                        log.warn("Redis template not available, falling back to local event publisher");
                        return new LocalEventPublisher(applicationEventPublisher);
                    }
                    return new RedisEventPublisher(redisTemplate, applicationEventPublisher);
                case "kafka":
                    // Kafka 구현 (향후 확장)
                    throw new UnsupportedOperationException("Kafka event publisher not implemented yet");
                default:
                    return new LocalEventPublisher(applicationEventPublisher);
            }
        } else {
            return new NoOpEventPublisher();
        }
    }

    /**
     * 캐시된 State Machine 영속화 (성능 최적화)
     */
    private static class CachedStateMachinePersist implements StateMachinePersist<MfaState, MfaEvent, String> {

        private final StateMachinePersist<MfaState, MfaEvent, String> delegate;
        private final Map<String, CachedContext> cache;
        private final int ttlMinutes;

        public CachedStateMachinePersist(StateMachinePersist<MfaState, MfaEvent, String> delegate,
                                         int maxSize, int ttlMinutes) {
            this.delegate = delegate;
            this.cache = new ConcurrentHashMap<>();
            this.ttlMinutes = ttlMinutes;

            // 주기적 캐시 정리
            ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor();
            cleaner.scheduleAtFixedRate(this::evictExpired, ttlMinutes, ttlMinutes, TimeUnit.MINUTES);
        }

        @Override
        public void write(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
            // 캐시에 저장
            cache.put(contextObj, new CachedContext(context));

            // 백그라운드로 실제 저장
            CompletableFuture.runAsync(() -> {
                try {
                    delegate.write(context, contextObj);
                } catch (Exception e) {
                    log.error("Failed to persist to delegate storage", e);
                }
            });
        }

        @Override
        public StateMachineContext<MfaState, MfaEvent> read(String contextObj) throws Exception {
            // 캐시 확인
            CachedContext cached = cache.get(contextObj);
            if (cached != null && !cached.isExpired(ttlMinutes)) {
                return cached.context;
            }

            // 캐시 미스 - delegate에서 읽기
            StateMachineContext<MfaState, MfaEvent> context = delegate.read(contextObj);
            if (context != null) {
                cache.put(contextObj, new CachedContext(context));
            }

            return context;
        }

        private void evictExpired() {
            cache.entrySet().removeIf(entry ->
                    entry.getValue().isExpired(ttlMinutes)
            );
        }

        private static class CachedContext {
            final StateMachineContext<MfaState, MfaEvent> context;
            final long timestamp;

            CachedContext(StateMachineContext<MfaState, MfaEvent> context) {
                this.context = context;
                this.timestamp = System.currentTimeMillis();
            }

            boolean isExpired(int ttlMinutes) {
                return System.currentTimeMillis() - timestamp > TimeUnit.MINUTES.toMillis(ttlMinutes);
            }
        }
    }

    /**
     * No-Op 이벤트 발행자 (비활성화용)
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
     * 로컬 이벤트 발행자 (단일 인스턴스)
     */
    private static class LocalEventPublisher extends MfaEventPublisherImpl {
        public LocalEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
            super(applicationEventPublisher);
        }
    }

    /**
     * Redis 이벤트 발행자 (분산 환경)
     */
    private static class RedisEventPublisher extends MfaEventPublisherImpl {
        private final RedisTemplate<String, String> redisTemplate;

        public RedisEventPublisher(RedisTemplate<String, String> redisTemplate,
                                   ApplicationEventPublisher applicationEventPublisher) {
            super(applicationEventPublisher);
            this.redisTemplate = redisTemplate;
        }

        @Override
        public void publishStateChange(String sessionId, MfaState state, MfaEvent event) {
            // 로컬 발행
            super.publishStateChange(sessionId, state, event);

            // Redis Pub/Sub으로 분산 발행
            Map<String, Object> message = new HashMap<>();
            message.put("sessionId", sessionId);
            message.put("state", state.name());
            message.put("event", event.name());
            message.put("timestamp", System.currentTimeMillis());

            try {
                redisTemplate.convertAndSend("mfa:events:state-change",
                        new ObjectMapper().writeValueAsString(message));
            } catch (Exception e) {
                log.error("Failed to publish event to Redis", e);
            }
        }
    }
}
