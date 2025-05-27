package io.springsecurity.springsecurity6x.security.token.store;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.config.redis.RedisEventPublisher;
import io.springsecurity.springsecurity6x.security.enums.TokenStoreType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * RefreshTokenStore 구현체를 생성하는 팩토리 클래스
 *
 * 설정된 TokenStoreType에 따라 적절한 구현체를 생성합니다:
 * - MEMORY: JwtRefreshTokenStore (기존 구현)
 * - REDIS: RedisRefreshTokenStore (새로운 구현)
 *
 * @since 2024.12
 */
@Slf4j
public class RefreshTokenStoreFactory {

    /**
     * RefreshTokenStore 구현체 생성 (기본 - 선택적 의존성 없이)
     *
     * @param tokenParser JWT 토큰 파서
     * @param props 인증 설정 프로퍼티
     * @param redisTemplate Redis 템플릿 (Redis 타입인 경우에만 필요)
     * @return RefreshTokenStore 구현체
     */
    public static RefreshTokenStore create(TokenParser tokenParser,
                                           AuthContextProperties props,
                                           StringRedisTemplate redisTemplate) {
        return create(tokenParser, props, redisTemplate, null, null);
    }

    /**
     * RefreshTokenStore 구현체 생성 (전체 의존성)
     *
     * @param tokenParser JWT 토큰 파서
     * @param props 인증 설정 프로퍼티
     * @param redisTemplate Redis 템플릿 (Redis 타입인 경우에만 필요)
     * @param lockService 분산 락 서비스 (optional)
     * @param eventPublisher 이벤트 발행 서비스 (optional)
     * @return RefreshTokenStore 구현체
     */
    public static RefreshTokenStore create(TokenParser tokenParser,
                                           AuthContextProperties props,
                                           StringRedisTemplate redisTemplate,
                                           RedisDistributedLockService lockService,
                                           RedisEventPublisher eventPublisher) {
        TokenStoreType storeType = props.getTokenStoreType();

        log.info("Creating RefreshTokenStore with type: {}", storeType);

        switch (storeType) {
            case MEMORY:
                log.info("Using in-memory refresh token store (single server mode)");
                return new JwtRefreshTokenStore(tokenParser, props);

            case REDIS:
                if (redisTemplate == null) {
                    log.error("Redis template is null but REDIS store type is configured. " +
                            "Falling back to MEMORY store.");
                    return new JwtRefreshTokenStore(tokenParser, props);
                }
                log.info("Using Redis-based refresh token store (distributed mode)");
                // lockService와 eventPublisher는 null일 수 있음 (선택적)
                return new RedisRefreshTokenStore(redisTemplate, tokenParser, props, lockService, eventPublisher);

            default:
                log.warn("Unknown token store type: {}. Using default MEMORY store.", storeType);
                return new JwtRefreshTokenStore(tokenParser, props);
        }
    }

    /**
     * RefreshTokenStore 구현체 생성 (Redis 미사용)
     *
     * @param tokenParser JWT 토큰 파서
     * @param props 인증 설정 프로퍼티
     * @return RefreshTokenStore 구현체
     */
    public static RefreshTokenStore create(TokenParser tokenParser,
                                           AuthContextProperties props) {
        return create(tokenParser, props, null, null, null);
    }
}