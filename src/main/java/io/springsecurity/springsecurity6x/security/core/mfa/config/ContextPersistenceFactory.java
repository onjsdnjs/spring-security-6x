package io.springsecurity.springsecurity6x.security.core.mfa.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.EnhancedHttpSessionContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.EnhancedRedisContextPersistence;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * ContextPersistence 팩토리 클래스
 * 설정에 따라 적절한 구현체를 생성
 */
@Slf4j
@RequiredArgsConstructor
public class ContextPersistenceFactory {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisDistributedLockService distributedLockService;
    private final ObjectMapper objectMapper;
    private final ContextPersistenceProperties properties;

    /**
     * 지정된 타입의 ContextPersistence 생성
     */
    public ContextPersistence createContextPersistence(ContextPersistenceProperties.PersistenceType type) {
        switch (type) {
            case SESSION:
                return createSessionContextPersistence();
            case REDIS:
                return createRedisContextPersistence();
            default:
                throw new IllegalArgumentException("Unsupported persistence type: " + type);
        }
    }

    /**
     * HttpSession 기반 ContextPersistence 생성
     */
    private ContextPersistence createSessionContextPersistence() {
        log.info("Creating HttpSession-based ContextPersistence with config: timeoutMinutes={}, maxSessions={}",
                properties.getSession().getTimeoutMinutes(),
                properties.getSession().getMaxConcurrentSessions());

        return new EnhancedHttpSessionContextPersistence(properties.getSession());
    }

    /**
     * Redis 기반 ContextPersistence 생성
     */
    private ContextPersistence createRedisContextPersistence() {
        log.info("Creating Redis-based ContextPersistence with config: ttlMinutes={}, compressionThreshold={}, circuitBreakerEnabled={}",
                properties.getRedis().getTtlMinutes(),
                properties.getRedis().getCompressionThreshold(),
                properties.getRedis().isCircuitBreakerEnabled());

        return new EnhancedRedisContextPersistence(
                redisTemplate,
                distributedLockService,
                objectMapper,
                properties.getRedis()
        );
    }

    /**
     * 동적으로 ContextPersistence 타입 변경
     */
    public ContextPersistence switchPersistenceType(ContextPersistenceProperties.PersistenceType newType) {
        log.info("Switching ContextPersistence type to: {}", newType);
        return createContextPersistence(newType);
    }
}