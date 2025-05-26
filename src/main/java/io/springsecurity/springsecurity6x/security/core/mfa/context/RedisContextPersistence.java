package io.springsecurity.springsecurity6x.security.core.mfa.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.io.*;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Redis 기반 ContextPersistence 구현체
 * 분산 환경에 최적화
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "security.mfa.persistence.type", havingValue = "redis")
@RequiredArgsConstructor
public class RedisContextPersistence implements ExtendedContextPersistence {

    @Qualifier("generalRedisTemplate")
    private final RedisTemplate<String, Object> redisTemplate;

    private final RedisDistributedLockService distributedLockService;
    private final ObjectMapper objectMapper;

    private static final String CONTEXT_PREFIX = "mfa:context:";
    private static final String SESSION_MAPPING_PREFIX = "mfa:session:";
    private static final int DEFAULT_TTL_MINUTES = 30;
    private static final int COMPRESSION_THRESHOLD = 1024; // 1KB

    // Circuit Breaker 상태
    private volatile boolean circuitOpen = false;
    private volatile long lastFailureTime = 0;
    private final AtomicLong operationCounter = new AtomicLong(0);
    private final AtomicLong failureCounter = new AtomicLong(0);
    private static final long CIRCUIT_OPEN_DURATION = 30000; // 30초

    @Override
    @Nullable
    public FactorContext contextLoad(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        String sessionId = session.getId();
        return loadContextBySessionId(sessionId);
    }

    @Override
    @Nullable
    public FactorContext loadContext(String mfaSessionId, HttpServletRequest request) {
        if (mfaSessionId == null) {
            return contextLoad(request);
        }

        try {
            operationCounter.incrementAndGet();

            // MFA 세션 ID로 직접 로드
            String contextKey = CONTEXT_PREFIX + mfaSessionId;
            return loadFromRedis(contextKey);
        } catch (Exception e) {
            failureCounter.incrementAndGet();
            log.error("Failed to load context for mfaSessionId: {}", mfaSessionId, e);
            handleFailure();
            return null;
        }
    }

    @Override
    public void saveContext(@Nullable FactorContext ctx, HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        String sessionId = session.getId();

        if (ctx == null) {
            deleteContextBySessionId(sessionId);
            return;
        }

        String mfaSessionId = ctx.getMfaSessionId();
        String contextKey = CONTEXT_PREFIX + mfaSessionId;
        String mappingKey = SESSION_MAPPING_PREFIX + sessionId;

        try {
            operationCounter.incrementAndGet();

            // 분산 락을 사용하여 동시성 제어
            distributedLockService.executeWithLock(
                    "context:save:" + mfaSessionId,
                    Duration.ofSeconds(5),
                    () -> {
                        // Redis 트랜잭션으로 원자적 저장
                        redisTemplate.execute(new SessionCallback<Object>() {
                            @Override
                            public Object execute(RedisOperations operations) {
                                operations.multi();

                                try {
                                    // 1. FactorContext 저장
                                    String serialized = serializeContext(ctx);
                                    operations.opsForValue().set(contextKey, serialized, DEFAULT_TTL_MINUTES, TimeUnit.MINUTES);

                                    // 2. 세션 ID와 MFA 세션 ID 매핑
                                    operations.opsForValue().set(mappingKey, mfaSessionId, DEFAULT_TTL_MINUTES, TimeUnit.MINUTES);

                                    // 3. 버전 정보
                                    String versionKey = contextKey + ":version";
                                    operations.opsForValue().set(versionKey, ctx.getVersion(), DEFAULT_TTL_MINUTES, TimeUnit.MINUTES);

                                } catch (Exception e) {
                                    log.error("Error during Redis transaction", e);
                                    operations.discard();
                                    return null;
                                }

                                return operations.exec();
                            }
                        });

                        log.debug("FactorContext saved to Redis: SessionId={}, MfaSessionId={}, State={}",
                                sessionId, mfaSessionId, ctx.getCurrentState());
                        handleSuccess();
                        return null;
                    }
            );
        } catch (Exception e) {
            failureCounter.incrementAndGet();
            log.error("Failed to save context to Redis", e);
            handleFailure();

            // Fallback: 세션에 저장
            session.setAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, ctx);
            log.warn("FactorContext saved to HttpSession as fallback for session: {}", mfaSessionId);
        }
    }

    @Override
    public void deleteContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();
            deleteContextBySessionId(sessionId);

            // 세션 속성도 제거
            session.removeAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        }
    }

    @Override
    public void deleteContext(String mfaSessionId) {
        if (mfaSessionId == null) {
            return;
        }

        try {
            operationCounter.incrementAndGet();

            String contextKey = CONTEXT_PREFIX + mfaSessionId;
            String versionKey = contextKey + ":version";

            // 트랜잭션으로 삭제
            redisTemplate.execute(new SessionCallback<Object>() {
                @Override
                public Object execute(RedisOperations operations) {
                    operations.multi();
                    operations.delete(contextKey);
                    operations.delete(versionKey);
                    return operations.exec();
                }
            });

            log.debug("FactorContext deleted from Redis: mfaSessionId={}", mfaSessionId);
            handleSuccess();

        } catch (Exception e) {
            failureCounter.incrementAndGet();
            log.error("Failed to delete context from Redis for mfaSessionId: {}", mfaSessionId, e);
            handleFailure();
        }
    }

    @Override
    public boolean exists(String mfaSessionId) {
        if (mfaSessionId == null) {
            return false;
        }

        try {
            String contextKey = CONTEXT_PREFIX + mfaSessionId;
            return Boolean.TRUE.equals(redisTemplate.hasKey(contextKey));
        } catch (Exception e) {
            log.error("Failed to check context existence for mfaSessionId: {}", mfaSessionId, e);
            return false;
        }
    }

    @Override
    public void refreshTtl(String mfaSessionId) {
        if (mfaSessionId == null) {
            return;
        }

        try {
            String contextKey = CONTEXT_PREFIX + mfaSessionId;
            String versionKey = contextKey + ":version";

            redisTemplate.expire(contextKey, DEFAULT_TTL_MINUTES, TimeUnit.MINUTES);
            redisTemplate.expire(versionKey, DEFAULT_TTL_MINUTES, TimeUnit.MINUTES);

            log.trace("TTL refreshed for context: {}", mfaSessionId);
        } catch (Exception e) {
            log.error("Failed to refresh TTL for context: {}", mfaSessionId, e);
        }
    }

    @Override
    public PersistenceType getPersistenceType() {
        return PersistenceType.REDIS;
    }

    /**
     * 세션 ID로 컨텍스트 로드
     */
    @Nullable
    private FactorContext loadContextBySessionId(String sessionId) {
        try {
            // 1. 세션 ID로 MFA 세션 ID 조회
            String mappingKey = SESSION_MAPPING_PREFIX + sessionId;
            String mfaSessionId = (String) redisTemplate.opsForValue().get(mappingKey);

            if (mfaSessionId == null) {
                log.trace("No MFA session mapping found for session: {}", sessionId);
                return null;
            }

            // 2. MFA 세션 ID로 컨텍스트 로드
            String contextKey = CONTEXT_PREFIX + mfaSessionId;
            return loadFromRedis(contextKey);

        } catch (Exception e) {
            log.error("Failed to load context for session: {}", sessionId, e);
            handleFailure();
            return null;
        }
    }

    /**
     * Redis에서 컨텍스트 로드
     */
    @Nullable
    private FactorContext loadFromRedis(String key) throws Exception {
        if (isCircuitOpen()) {
            log.warn("Circuit breaker is open, skipping Redis load");
            return null;
        }

        Object data = redisTemplate.opsForValue().get(key);
        if (data == null) {
            return null;
        }

        String serialized = (String) data;
        FactorContext context = deserializeContext(serialized);

        // TTL 갱신
        redisTemplate.expire(key, DEFAULT_TTL_MINUTES, TimeUnit.MINUTES);

        log.debug("FactorContext loaded from Redis: Key={}, State={}",
                key, context.getCurrentState());

        handleSuccess();
        return context;
    }

    /**
     * 세션 ID로 컨텍스트 삭제
     */
    private void deleteContextBySessionId(String sessionId) {
        try {
            // 1. 매핑 정보 조회
            String mappingKey = SESSION_MAPPING_PREFIX + sessionId;
            String mfaSessionId = (String) redisTemplate.opsForValue().get(mappingKey);

            if (mfaSessionId != null) {
                // 2. 트랜잭션으로 모두 삭제
                redisTemplate.execute(new SessionCallback<Object>() {
                    @Override
                    public Object execute(RedisOperations operations) {
                        operations.multi();

                        // 컨텍스트 삭제
                        operations.delete(CONTEXT_PREFIX + mfaSessionId);
                        operations.delete(CONTEXT_PREFIX + mfaSessionId + ":version");

                        // 매핑 삭제
                        operations.delete(mappingKey);

                        return operations.exec();
                    }
                });

                log.debug("FactorContext deleted from Redis: SessionId={}, MfaSessionId={}",
                        sessionId, mfaSessionId);
            }
        } catch (Exception e) {
            log.error("Failed to delete context from Redis", e);
        }
    }

    /**
     * 컨텍스트 직렬화
     */
    private String serializeContext(FactorContext context) throws IOException {
        // Java 직렬화 사용
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {

            oos.writeObject(context);
            byte[] data = baos.toByteArray();

            // 압축 여부 결정
            if (data.length > COMPRESSION_THRESHOLD) {
                data = compress(data);
                return "GZIP:" + Base64.getEncoder().encodeToString(data);
            } else {
                return "RAW:" + Base64.getEncoder().encodeToString(data);
            }
        }
    }

    /**
     * 컨텍스트 역직렬화
     */
    private FactorContext deserializeContext(String serialized) throws IOException, ClassNotFoundException {
        byte[] data;

        if (serialized.startsWith("GZIP:")) {
            data = Base64.getDecoder().decode(serialized.substring(5));
            data = decompress(data);
        } else if (serialized.startsWith("RAW:")) {
            data = Base64.getDecoder().decode(serialized.substring(4));
        } else {
            // 구버전 호환성
            data = Base64.getDecoder().decode(serialized);
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (FactorContext) ois.readObject();
        }
    }

    /**
     * 데이터 압축
     */
    private byte[] compress(byte[] data) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(data);
            gzip.finish();
            return baos.toByteArray();
        }
    }

    /**
     * 데이터 압축 해제
     */
    private byte[] decompress(byte[] compressed) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
             GZIPInputStream gzip = new GZIPInputStream(bais)) {
            return gzip.readAllBytes();
        }
    }

    /**
     * Circuit Breaker 상태 확인
     */
    private boolean isCircuitOpen() {
        if (circuitOpen) {
            if (System.currentTimeMillis() - lastFailureTime > CIRCUIT_OPEN_DURATION) {
                circuitOpen = false;
                log.info("Circuit breaker closed");
            }
        }
        return circuitOpen;
    }

    /**
     * 성공 처리
     */
    private void handleSuccess() {
        circuitOpen = false;
    }

    /**
     * 실패 처리
     */
    private void handleFailure() {
        lastFailureTime = System.currentTimeMillis();
        circuitOpen = true;
        log.warn("Circuit breaker opened due to Redis failure");
    }

    /**
     * Redis 통계 정보 반환
     */
    public Map<String, Object> getRedisStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalOperations", operationCounter.get());
        stats.put("failureCount", failureCounter.get());
        stats.put("circuitOpen", circuitOpen);
        stats.put("persistenceType", getPersistenceType().name());
        return stats;
    }
}