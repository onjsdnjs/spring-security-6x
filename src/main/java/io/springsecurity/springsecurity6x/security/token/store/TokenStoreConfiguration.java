package io.springsecurity.springsecurity6x.security.token.store;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.config.redis.RedisEventPublisher;
import io.springsecurity.springsecurity6x.security.enums.TokenStoreType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * 토큰 저장소 관련 설정
 *
 * TokenStoreType 설정에 따라 적절한 RefreshTokenStore 구현체를 생성합니다.
 * - MEMORY: 단일 서버 환경용 (기본값)
 * - REDIS: 분산 서버 환경용
 *
 * @since 2024.12
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class TokenStoreConfiguration {

    private final AuthContextProperties authContextProperties;

    /**
     * RefreshTokenStore 빈 생성
     *
     * @param tokenParser JWT 토큰 파서
     * @param redisTemplate Redis 템플릿 (optional)
     * @param lockService 분산 락 서비스 (optional)
     * @param eventPublisher 이벤트 발행 서비스 (optional)
     * @return RefreshTokenStore 구현체
     */
    @Bean
    @ConditionalOnMissingBean(RefreshTokenStore.class)
    public RefreshTokenStore refreshTokenStore(
            TokenParser tokenParser,
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisDistributedLockService lockService,
            @Autowired(required = false) RedisEventPublisher eventPublisher) {

        TokenStoreType storeType = authContextProperties.getTokenStoreType();

        if (storeType == TokenStoreType.REDIS && redisTemplate == null) {
            log.warn("REDIS token store is configured but Redis is not available. " +
                    "Please ensure Redis dependencies and configuration are properly set. " +
                    "Falling back to MEMORY store.");
        }

        return RefreshTokenStoreFactory.create(tokenParser, authContextProperties, redisTemplate, lockService, eventPublisher);
    }

    /**
     * RedisDistributedLockService 빈 생성
     * Redis가 활성화된 경우에만 생성됩니다.
     */
    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    @ConditionalOnMissingBean(RedisDistributedLockService.class)
    public RedisDistributedLockService redisDistributedLockService(
            @Autowired(required = false) RedisTemplate<String, String> redisTemplate) {

        if (redisTemplate != null) {
            log.info("Creating RedisDistributedLockService");
            return new RedisDistributedLockService(redisTemplate);
        }
        return null;
    }
}