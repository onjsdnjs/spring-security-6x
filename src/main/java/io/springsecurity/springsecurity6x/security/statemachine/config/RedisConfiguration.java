package io.springsecurity.springsecurity6x.security.statemachine.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis 설정
 * State Machine Redis가 활성화된 경우에만 로드
 */
@Slf4j
@Configuration
@ConditionalOnClass(RedisTemplate.class)
@AutoConfigureAfter(RedisAutoConfiguration.class)
@ConditionalOnProperty(prefix = "security.statemachine.redis", name = "enabled", havingValue = "true")
public class RedisConfiguration {

    /**
     * State Machine용 RedisTemplate
     * byte[] 직렬화를 사용하여 State Machine 데이터 저장
     */
    @Bean(name = "stateMachineRedisTemplate")
    @ConditionalOnMissingBean(name = "stateMachineRedisTemplate")
    public RedisTemplate<String, byte[]> stateMachineRedisTemplate(RedisConnectionFactory connectionFactory) {

        log.info("Creating stateMachineRedisTemplate bean");

        RedisTemplate<String, byte[]> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Key는 String 직렬화
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Value는 byte[] 그대로 사용
        template.setValueSerializer(RedisSerializer.byteArray());
        template.setHashValueSerializer(RedisSerializer.byteArray());

        // 초기화
        template.afterPropertiesSet();

        log.info("stateMachineRedisTemplate bean created successfully");

        return template;
    }
}