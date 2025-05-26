/*
package io.springsecurity.springsecurity6x.security.statemachine.core;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;


import java.util.concurrent.TimeUnit;

*/
/**
 * Spring State Machine 4.0.0을 위한 Redis 영속화 구현
 * KryoStateMachineSerialisationService를 사용하여 직렬화
 *//*

public class RedisStateMachinePersist<S, E> implements StateMachinePersist<S, E, String> {

    private final RedisTemplate<String, byte[]> redisTemplate;
    private final String keyPrefix;
    private final int ttlMinutes;
    private final KryoStateMachineSerialisationService<S, E> serializer;

    public RedisStateMachinePersist(RedisTemplate<String, byte[]> redisTemplate,
                                      String keyPrefix,
                                      int ttlMinutes) {
        this.redisTemplate = redisTemplate;
        this.keyPrefix = keyPrefix;
        this.ttlMinutes = ttlMinutes;
        this.serializer = new KryoStateMachineSerialisationService<>();
    }

    @Override
    public void write(StateMachineContext<S, E> context, String contextObj) throws Exception {
        String key = keyPrefix + contextObj;
        byte[] data = serializer.serialiseStateMachineContext(context);

        redisTemplate.opsForValue().set(key, data, ttlMinutes, TimeUnit.MINUTES);
    }

    @Override
    public StateMachineContext<S, E> read(String contextObj) throws Exception {
        String key = keyPrefix + contextObj;
        byte[] data = redisTemplate.opsForValue().get(key);

        if (data == null) {
            return null;
        }

        return serializer.deserialiseStateMachineContext(data);
    }
}*/
