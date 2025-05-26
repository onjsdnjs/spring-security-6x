package io.springsecurity.springsecurity6x.security.core.mfa.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.config.ContextPersistenceProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * 향상된 Redis 기반 ContextPersistence
 */
@Slf4j
public class EnhancedRedisContextPersistence extends RedisContextPersistence {

    private final ContextPersistenceProperties.RedisConfig config;

    public EnhancedRedisContextPersistence(
            RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService distributedLockService,
            ObjectMapper objectMapper,
            ContextPersistenceProperties.RedisConfig config) {

        super(redisTemplate, distributedLockService, objectMapper);
        this.config = config;

        log.info("Enhanced Redis ContextPersistence initialized with config: {}", config);
    }

    // 설정 기반 동작을 위한 오버라이드 메서드들을 여기에 구현
    // 예: TTL, 압축 임계값, Circuit Breaker 설정 등
}
