package io.springsecurity.springsecurity6x.security.config.redis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * 통합 Redis 설정 - 간소화 버전
 *
 * 삭제/수정 사항:
 * - @ConditionalOnMissingBean 제거 (불필요)
 * - stateMachinePersistRedisTemplate 삭제 (사용 안함)
 * - 중복된 설정 제거
 */
@Slf4j
@Configuration
@ConditionalOnClass(RedisTemplate.class)
@AutoConfigureAfter(RedisAutoConfiguration.class)
public class UnifiedRedisConfiguration {

    /**
     * 범용 RedisTemplate (JSON 직렬화)
     * - 이벤트 발행
     * - 일반 데이터 저장
     */
    @Bean(name = "generalRedisTemplate")
    @Primary
    public RedisTemplate<String, Object> generalRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating general purpose RedisTemplate with JSON serialization");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // 직렬화 설정
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer();

        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        template.setDefaultSerializer(jsonSerializer);

        // 중요: 트랜잭션 비활성화 (연결 재사용)
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * State Machine 전용 RedisTemplate (String 직렬화)
     * - State Machine 데이터 저장
     * - 분산 락
     */
    @Bean(name = "stateMachineRedisTemplate")
    public RedisTemplate<String, Object> stateMachineRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating State Machine RedisTemplate with String serialization");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // String 직렬화 사용 (성능 최적화)
        StringRedisSerializer serializer = new StringRedisSerializer();
        template.setKeySerializer(serializer);
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(serializer);
        template.setHashValueSerializer(serializer);

        // 중요: 트랜잭션 비활성화
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    @Primary
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory connectionFactory) {
        StringRedisTemplate template = new StringRedisTemplate();
        template.setConnectionFactory(connectionFactory);
        template.setEnableTransactionSupport(false);  // 이거!
        template.afterPropertiesSet();
        return template;
    }

    /**
     * Redis 메시지 리스너 컨테이너
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(RedisConnectionFactory connectionFactory) {
        log.info("Creating Redis message listener container");

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        return container;
    }
}