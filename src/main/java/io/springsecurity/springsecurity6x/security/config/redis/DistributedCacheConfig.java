package io.springsecurity.springsecurity6x.security.config.redis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

/**
 * 분산 캐시 설정
 * Redis를 사용한 분산 캐싱 구성
 */
@Slf4j
@Configuration
@EnableCaching
public class DistributedCacheConfig {

    /**
     * Redis 캐시 설정 커스터마이저
     */
    @Bean
    public RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
        return (builder) -> {
            // 기본 캐시 설정
            RedisCacheConfiguration defaultConfig = RedisCacheConfiguration.defaultCacheConfig()
                    .entryTtl(Duration.ofMinutes(10))
                    .serializeKeysWith(RedisSerializationContext.SerializationPair
                            .fromSerializer(new StringRedisSerializer()))
                    .serializeValuesWith(RedisSerializationContext.SerializationPair
                            .fromSerializer(new GenericJackson2JsonRedisSerializer()))
                    .disableCachingNullValues();

            // 사용자 캐시 - 30분 TTL
            RedisCacheConfiguration userCacheConfig = defaultConfig
                    .entryTtl(Duration.ofMinutes(30))
                    .prefixCacheNameWith("user:");

            // MFA 캐시 - 5분 TTL
            RedisCacheConfiguration mfaCacheConfig = defaultConfig
                    .entryTtl(Duration.ofMinutes(5))
                    .prefixCacheNameWith("mfa:");

            // 토큰 캐시 - 1시간 TTL
            RedisCacheConfiguration tokenCacheConfig = defaultConfig
                    .entryTtl(Duration.ofHours(1))
                    .prefixCacheNameWith("token:");

            builder
                    .cacheDefaults(defaultConfig)
                    .withCacheConfiguration("userCache", userCacheConfig)
                    .withCacheConfiguration("mfaCache", mfaCacheConfig)
                    .withCacheConfiguration("tokenCache", tokenCacheConfig);

            log.info("Distributed cache configuration completed");
        };
    }
}
