package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Redis 기반 State Machine 영속화 구현
 * StateMachineContext를 Redis에 저장하고 복원
 */
@Slf4j
@RequiredArgsConstructor
public class RedisStateMachinePersist implements StateMachinePersist<MfaState, MfaEvent, String> {

    private final RedisTemplate<String, byte[]> redisTemplate;
    private final int ttlMinutes;

    private static final String KEY_PREFIX = "mfa:statemachine:";

    @Override
    public void write(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
        String key = generateKey(contextObj);
        log.debug("Persisting state machine context to Redis with key: {}", key);

        try {
            // StateMachineContext를 직렬화
            byte[] serialized = serialize(context);

            // Redis에 저장 (TTL 적용)
            redisTemplate.opsForValue().set(key, serialized, ttlMinutes, TimeUnit.MINUTES);

            log.info("State machine context persisted successfully for session: {}", contextObj);

        } catch (Exception e) {
            log.error("Failed to persist state machine context for session: {}", contextObj, e);
            throw new RuntimeException("Failed to persist state machine context", e);
        }
    }

    @Override
    public StateMachineContext<MfaState, MfaEvent> read(String contextObj) throws Exception {
        String key = generateKey(contextObj);
        log.debug("Reading state machine context from Redis with key: {}", key);

        try {
            byte[] serialized = redisTemplate.opsForValue().get(key);

            if (serialized == null) {
                log.debug("No state machine context found for session: {}", contextObj);
                return null;
            }

            // 역직렬화
            StateMachineContext<MfaState, MfaEvent> context = deserialize(serialized);

            // TTL 갱신
            redisTemplate.expire(key, ttlMinutes, TimeUnit.MINUTES);

            log.info("State machine context loaded successfully for session: {}", contextObj);
            return context;

        } catch (Exception e) {
            log.error("Failed to read state machine context for session: {}", contextObj, e);
            throw new RuntimeException("Failed to read state machine context", e);
        }
    }

    /**
     * 상태 머신 컨텍스트 삭제
     */
    public void delete(String contextObj) {
        String key = generateKey(contextObj);
        log.debug("Deleting state machine context from Redis with key: {}", key);

        try {
            Boolean deleted = redisTemplate.delete(key);
            if (Boolean.TRUE.equals(deleted)) {
                log.info("State machine context deleted for session: {}", contextObj);
            } else {
                log.warn("No state machine context found to delete for session: {}", contextObj);
            }
        } catch (Exception e) {
            log.error("Failed to delete state machine context for session: {}", contextObj, e);
        }
    }

    /**
     * Redis 키 생성
     */
    private String generateKey(String sessionId) {
        return KEY_PREFIX + sessionId;
    }

    /**
     * StateMachineContext 직렬화
     * 간단한 구조로 변환하여 직렬화
     */
    private byte[] serialize(StateMachineContext<MfaState, MfaEvent> context) throws IOException {
        Map<String, Object> data = new HashMap<>();

        // 기본 정보
        data.put("id", context.getId());
        data.put("state", context.getState() != null ? context.getState().name() : null);
        data.put("event", context.getEvent() != null ? context.getEvent().name() : null);

        // ExtendedState 변수들
        if (context.getExtendedState() != null) {
            Map<Object, Object> variables = context.getExtendedState().getVariables();
            Map<String, Object> serializedVars = new HashMap<>();

            for (Map.Entry<Object, Object> entry : variables.entrySet()) {
                String key = entry.getKey().toString();
                Object value = entry.getValue();

                // 직렬화 가능한 형태로 변환
                if (value instanceof Serializable) {
                    serializedVars.put(key, value);
                } else {
                    // 직렬화 불가능한 객체는 문자열로 변환
                    serializedVars.put(key, value.toString());
                }
            }

            data.put("variables", serializedVars);
        }

        // 이벤트 헤더
        if (context.getEventHeaders() != null) {
            data.put("headers", context.getEventHeaders());
        }

        // 히스토리 상태들
        if (context.getHistoryStates() != null) {
            Map<String, String> historyStates = new HashMap<>();
            context.getHistoryStates().forEach((k, v) -> {
                if (v != null) {
                    historyStates.put(k.toString(), v.name());
                }
            });
            data.put("historyStates", historyStates);
        }

        // Java 직렬화
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(data);
            return baos.toByteArray();
        }
    }

    /**
     * StateMachineContext 역직렬화
     */
    @SuppressWarnings("unchecked")
    private StateMachineContext<MfaState, MfaEvent> deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {

            Map<String, Object> map = (Map<String, Object>) ois.readObject();

            // 기본 정보 복원
            String id = (String) map.get("id");
            MfaState state = map.get("state") != null ?
                    MfaState.valueOf((String) map.get("state")) : null;
            MfaEvent event = map.get("event") != null ?
                    MfaEvent.valueOf((String) map.get("event")) : null;

            // ExtendedState 변수 복원
            Map<Object, Object> variables = new HashMap<>();
            if (map.get("variables") instanceof Map) {
                variables.putAll((Map<Object, Object>) map.get("variables"));
            }

            // 이벤트 헤더 복원
            Map<String, Object> headers = new HashMap<>();
            if (map.get("headers") instanceof Map) {
                headers.putAll((Map<String, Object>) map.get("headers"));
            }

            // ExtendedState 생성
            ExtendedState extendedState = new DefaultExtendedState();
            extendedState.getVariables().putAll(variables);

            // 히스토리 상태 복원
            Map<Object, MfaState> historyStates = new HashMap<>();
            if (map.get("historyStates") instanceof Map) {
                Map<String, String> savedHistory = (Map<String, String>) map.get("historyStates");
                savedHistory.forEach((k, v) -> {
                    historyStates.put(k, MfaState.valueOf(v));
                });
            }

            // DefaultStateMachineContext 생성
            // 생성자: DefaultStateMachineContext(List<StateMachineContext<S,E>> childs, S state, E event,
            //                                    Map<String,Object> eventHeaders, ExtendedState extendedState)
            return new DefaultStateMachineContext<MfaState, MfaEvent>(
                    null,  // childs (하위 컨텍스트 없음)
                    state,  // 현재 상태
                    event,  // 마지막 이벤트
                    headers, // 이벤트 헤더
                    extendedState  // ExtendedState
            );
        }
    }

    /**
     * 모든 세션의 상태 머신 컨텍스트 조회 (관리 목적)
     */
    public Map<String, StateMachineContext<MfaState, MfaEvent>> readAll() {
        Map<String, StateMachineContext<MfaState, MfaEvent>> contexts = new HashMap<>();

        try {
            // 패턴 매칭으로 모든 키 조회
            var keys = redisTemplate.keys(KEY_PREFIX + "*");
            if (keys != null) {
                for (String key : keys) {
                    String sessionId = key.substring(KEY_PREFIX.length());
                    try {
                        StateMachineContext<MfaState, MfaEvent> context = read(sessionId);
                        if (context != null) {
                            contexts.put(sessionId, context);
                        }
                    } catch (Exception e) {
                        log.warn("Failed to read context for key: {}", key, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to read all state machine contexts", e);
        }

        return contexts;
    }
}