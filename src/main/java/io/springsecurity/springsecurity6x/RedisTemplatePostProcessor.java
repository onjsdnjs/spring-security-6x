package io.springsecurity.springsecurity6x;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;

/**
 * 모든 RedisTemplate의 트랜잭션을 강제로 비활성화
 * Spring Data Redis 버전에 관계없이 작동
 */
@Slf4j
@Component
public class RedisTemplatePostProcessor {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @PostConstruct
    public void checkRedisConfig() {
        log.info("RedisTemplate class: {}", redisTemplate.getClass());
//        log.info("Transaction support: {}", redisTemplate.isEnableTransactionSupport());
    }
}