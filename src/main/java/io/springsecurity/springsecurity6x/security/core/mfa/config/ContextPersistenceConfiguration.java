package io.springsecurity.springsecurity6x.security.core.mfa.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.context.*;
import io.springsecurity.springsecurity6x.security.statemachine.config.StateMachineProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachinePersist;

/**
 * ContextPersistence 통합 설정 클래스
 * 환경에 따라 적절한 저장 전략을 선택
 */
@Slf4j
@Configuration
@EnableConfigurationProperties({
        ContextPersistenceProperties.class,
        ContextPersistenceMetricsProperties.class
})
@RequiredArgsConstructor
public class ContextPersistenceConfiguration {

    private final ContextPersistenceProperties properties;

    /**
     * 기본 ContextPersistence Bean
     * 설정에 따라 적절한 구현체를 선택
     */
    @Bean
    @Primary
    public ContextPersistence contextPersistence(
            ContextPersistenceFactory factory) {

        ContextPersistence persistence = factory.createContextPersistence(properties.getType());

        log.info("ContextPersistence configured: type={}, description={}",
                properties.getType(),
                persistence instanceof ExtendedContextPersistence ?
                        ((ExtendedContextPersistence) persistence).getPersistenceType().getDescription() :
                        "Unknown");

        return persistence;
    }

    /**
     * ContextPersistence 팩토리 Bean
     */
    @Bean
    public ContextPersistenceFactory contextPersistenceFactory(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService distributedLockService,
            ObjectMapper objectMapper) {

        return new ContextPersistenceFactory(
                redisTemplate,
                distributedLockService,
                objectMapper,
                properties
        );
    }

    /**
     * ContextPersistence 모니터링 서비스
     */
    @Bean
    @ConditionalOnProperty(name = "security.mfa.persistence.monitoring.enabled", havingValue = "true", matchIfMissing = true)
    public ContextPersistenceMonitoringService monitoringService(
            ContextPersistence contextPersistence,
            ContextPersistenceMetricsProperties metricsProperties) {

        return new ContextPersistenceMonitoringService(contextPersistence, metricsProperties);
    }

    /**
     * ContextPersistence 헬스 체크 서비스
     */
    @Bean
    public ContextPersistenceHealthIndicator healthIndicator(
            ContextPersistence contextPersistence) {

        return new ContextPersistenceHealthIndicator(contextPersistence);
    }
}
