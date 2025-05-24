package io.springsecurity.springsecurity6x.security.config.redis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;

/**
 * 분산 세션 설정
 * Redis를 사용한 HTTP 세션 공유
 */
@Slf4j
@Configuration
@EnableRedisHttpSession(
        maxInactiveIntervalInSeconds = 1800,  // 30분
        redisNamespace = "spring:session"
)
public class DistributedSessionConfig extends AbstractHttpSessionApplicationInitializer {

    /**
     * 세션 직렬화 설정
     */
    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return new GenericJackson2JsonRedisSerializer();
    }

    public DistributedSessionConfig() {
        log.info("Distributed session management enabled with Redis");
    }
}
