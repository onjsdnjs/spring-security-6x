package io.springsecurity.springsecurity6x.security.statemachine.core.persist;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * 장애 복구를 고려한 Redis 기반 State Machine 영속화
 */
@Slf4j
@RequiredArgsConstructor
public class ResilientRedisStateMachinePersist implements StateMachinePersist<MfaState, MfaEvent, String> {

    private final RedisTemplate<String, String> redisTemplate;
    private final StateMachinePersist<MfaState, MfaEvent, String> fallbackPersist;
    private final int ttlMinutes;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String KEY_PREFIX = "mfa:statemachine:";
    private static final String BACKUP_PREFIX = "mfa:statemachine:backup:";

    // Circuit Breaker 상태
    private volatile CircuitState circuitState = CircuitState.CLOSED;
    private volatile long lastFailureTime = 0;
    private volatile int failureCount = 0;

    private static final int FAILURE_THRESHOLD = 3;
    private static final long CIRCUIT_OPEN_DURATION = 30000; // 30초

    @Override
    public void write(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
        if (isCircuitOpen()) {
            log.warn("Circuit is open, using fallback for session: {}", contextObj);
            writeFallback(context, contextObj);
            return;
        }

        String key = KEY_PREFIX + contextObj;
        String backupKey = BACKUP_PREFIX + contextObj;

        try {
            // 컨텍스트 직렬화
            String serialized = serialize(context);

            // 압축 (큰 데이터의 경우)
            if (serialized.length() > 1024) {
                serialized = compress(serialized);
            }

            // 메인 키에 저장
            redisTemplate.opsForValue().set(key, serialized, ttlMinutes, TimeUnit.MINUTES);

            // 백업 저장 (더 긴 TTL)
            redisTemplate.opsForValue().set(backupKey, serialized, ttlMinutes * 2, TimeUnit.MINUTES);

            // 성공 시 Circuit 상태 업데이트
            onSuccess();

            log.debug("State machine context persisted for session: {}", contextObj);

        } catch (RedisConnectionFailureException e) {
            onFailure();
            log.error("Redis connection failed, using fallback for session: {}", contextObj);
            writeFallback(context, contextObj);
            throw e;
        } catch (Exception e) {
            log.error("Failed to persist state machine context for session: {}", contextObj, e);
            throw e;
        }
    }

    @Override
    public StateMachineContext<MfaState, MfaEvent> read(String contextObj) throws Exception {
        if (isCircuitOpen()) {
            log.warn("Circuit is open, using fallback for session: {}", contextObj);
            return readFallback(contextObj);
        }

        String key = KEY_PREFIX + contextObj;
        String backupKey = BACKUP_PREFIX + contextObj;

        try {
            // 메인 키에서 읽기 시도
            String serialized = redisTemplate.opsForValue().get(key);

            // 메인 키가 없으면 백업에서 읽기
            if (serialized == null) {
                serialized = redisTemplate.opsForValue().get(backupKey);

                if (serialized != null) {
                    log.warn("Main key not found, restored from backup for session: {}", contextObj);
                    // 메인 키 복원
                    redisTemplate.opsForValue().set(key, serialized, ttlMinutes, TimeUnit.MINUTES);
                }
            }

            if (serialized == null) {
                log.debug("No state machine context found for session: {}", contextObj);
                return null;
            }

            // 압축 해제 (필요한 경우)
            if (isCompressed(serialized)) {
                serialized = decompress(serialized);
            }

            // 역직렬화
            StateMachineContext<MfaState, MfaEvent> context = deserialize(serialized);

            // TTL 갱신
            redisTemplate.expire(key, ttlMinutes, TimeUnit.MINUTES);

            // 성공 시 Circuit 상태 업데이트
            onSuccess();

            return context;

        } catch (RedisConnectionFailureException e) {
            onFailure();
            log.error("Redis connection failed, using fallback for session: {}", contextObj);
            return readFallback(contextObj);
        } catch (Exception e) {
            log.error("Failed to read state machine context for session: {}", contextObj, e);
            throw e;
        }
    }

    /**
     * 컨텍스트 직렬화 (간소화된 형식)
     */
    private String serialize(StateMachineContext<MfaState, MfaEvent> context) throws Exception {
        Map<String, Object> data = new HashMap<>();

        // 필수 정보만 저장
        data.put("state", context.getState() != null ? context.getState().name() : null);
        data.put("event", context.getEvent() != null ? context.getEvent().name() : null);

        // ExtendedState 변수 중 중요한 것만
        if (context.getExtendedState() != null) {
            Map<String, Object> variables = new HashMap<>();
            context.getExtendedState().getVariables().forEach((k, v) -> {
                if (isImportantVariable(k.toString()) && v instanceof Serializable) {
                    variables.put(k.toString(), v);
                }
            });
            data.put("variables", variables);
        }

        // JSON 형식으로 직렬화
        return objectMapper.writeValueAsString(data);
    }

    /**
     * 컨텍스트 역직렬화
     */
    private StateMachineContext<MfaState, MfaEvent> deserialize(String data) throws Exception {
        Map<String, Object> map = objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});

        MfaState state = map.get("state") != null ?
                MfaState.valueOf((String) map.get("state")) : null;
        MfaEvent event = map.get("event") != null ?
                MfaEvent.valueOf((String) map.get("event")) : null;

        // ExtendedState 복원
        ExtendedState extendedState = new DefaultExtendedState();
        if (map.get("variables") instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> variables = (Map<String, Object>) map.get("variables");
            variables.forEach((k, v) -> extendedState.getVariables().put(k, v));
        }

        return new DefaultStateMachineContext<>(
                null,  // childs
                state,
                event,
                null,  // eventHeaders
                extendedState
        );
    }

    /**
     * 중요한 변수인지 확인
     */
    private boolean isImportantVariable(String key) {
        return key.equals("mfaSessionId") ||
                key.equals("username") ||
                key.equals("currentStepId") ||
                key.equals("retryCount") ||
                key.equals("completedFactors") ||
                key.equals("version") ||
                key.equals("createdAt");
    }

    /**
     * 압축
     */
    private String compress(String data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(data.getBytes(StandardCharsets.UTF_8));
        }
        return "GZIP:" + Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    /**
     * 압축 해제
     */
    private String decompress(String compressed) throws IOException {
        if (!compressed.startsWith("GZIP:")) {
            return compressed;
        }

        byte[] bytes = Base64.getDecoder().decode(compressed.substring(5));
        try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
             GZIPInputStream gzip = new GZIPInputStream(bais)) {
            return new String(gzip.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * 압축 여부 확인
     */
    private boolean isCompressed(String data) {
        return data != null && data.startsWith("GZIP:");
    }

    /**
     * Circuit Breaker 상태 확인
     */
    private boolean isCircuitOpen() {
        if (circuitState == CircuitState.OPEN) {
            // 충분한 시간이 지났으면 Half-Open으로 전환
            if (System.currentTimeMillis() - lastFailureTime > CIRCUIT_OPEN_DURATION) {
                circuitState = CircuitState.HALF_OPEN;
                log.info("Circuit breaker transitioned to HALF_OPEN");
            }
        }
        return circuitState == CircuitState.OPEN;
    }

    /**
     * 성공 시 Circuit 상태 업데이트
     */
    private void onSuccess() {
        if (circuitState == CircuitState.HALF_OPEN) {
            circuitState = CircuitState.CLOSED;
            failureCount = 0;
            log.info("Circuit breaker closed after successful operation");
        }
    }

    /**
     * 실패 시 Circuit 상태 업데이트
     */
    private void onFailure() {
        lastFailureTime = System.currentTimeMillis();
        failureCount++;

        if (failureCount >= FAILURE_THRESHOLD) {
            circuitState = CircuitState.OPEN;
            log.warn("Circuit breaker opened after {} failures", failureCount);
        }
    }

    /**
     * Fallback 쓰기
     */
    private void writeFallback(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
        if (fallbackPersist != null) {
            fallbackPersist.write(context, contextObj);
        } else {
            log.warn("No fallback persist available for session: {}", contextObj);
        }
    }

    /**
     * Fallback 읽기
     */
    private StateMachineContext<MfaState, MfaEvent> readFallback(String contextObj) throws Exception {
        if (fallbackPersist != null) {
            return fallbackPersist.read(contextObj);
        } else {
            log.warn("No fallback persist available for session: {}", contextObj);
            return null;
        }
    }

    /**
     * Circuit 상태
     */
    private enum CircuitState {
        CLOSED,     // 정상 작동
        OPEN,       // 차단 상태
        HALF_OPEN   // 테스트 상태
    }
}