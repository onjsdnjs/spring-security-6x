package io.springsecurity.springsecurity6x.security.core.mfa.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.context.*;
import io.springsecurity.springsecurity6x.security.statemachine.config.StateMachineProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachinePersist;

/**
 * ContextPersistence 설정
 * - 설정에 따라 Session 또는 Redis 기반 구현 선택
 * - State Machine과의 통합 저장 지원
 */
@Slf4j
@Configuration
public class ContextPersistenceConfiguration {

    /**
     * 기본 HTTP Session 기반 구현
     */
    @Bean
    public HttpSessionContextPersistence httpSessionContextPersistence() {
        log.info("Creating HttpSessionContextPersistence bean");
        return new HttpSessionContextPersistence();
    }

    /**
     * Redis 기반 구현 (Redis 사용 시)
     */
    @Bean
    @ConditionalOnProperty(
            prefix = "security.mfa.context-persistence",
            name = "type",
            havingValue = "redis"
    )
    public RedisContextPersistence redisContextPersistence(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService distributedLockService,
            ObjectMapper objectMapper) {
        log.info("Creating RedisContextPersistence bean");
        return new RedisContextPersistence(redisTemplate, distributedLockService, objectMapper);
    }

    /**
     * 통합 ContextPersistence (Primary)
     */
    @Bean
    @Primary
    public ContextPersistence contextPersistence(
            @Value("${security.mfa.context-persistence.type:session}") String persistenceType,
            @Value("${security.mfa.context-persistence.atomic-save:true}") boolean atomicSaveEnabled,
            HttpSessionContextPersistence sessionPersistence,
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService distributedLockService,
            ObjectMapper objectMapper,
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist,
            StateMachineProperties stateMachineProperties) {

        log.info("Creating UnifiedContextPersistence with type: {}, atomicSave: {}",
                persistenceType, atomicSaveEnabled);

        return new UnifiedContextPersistence(
                persistenceType,
                atomicSaveEnabled,
                sessionPersistence,
                redisTemplate,
                distributedLockService,
                objectMapper,
                stateMachinePersist,
                stateMachineProperties
        );
    }
}
