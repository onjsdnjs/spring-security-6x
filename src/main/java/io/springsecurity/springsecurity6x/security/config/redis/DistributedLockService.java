package io.springsecurity.springsecurity6x.security.config.redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

/**
 * 분산 락 서비스
 * Redis를 사용한 분산 환경에서의 동시성 제어
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DistributedLockService {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String LOCK_PREFIX = "distributed:lock:";

    /**
     * 분산 락 획득
     */
    public String acquireLock(String resourceKey, Duration leaseTime) {
        String lockKey = LOCK_PREFIX + resourceKey;
        String lockValue = UUID.randomUUID().toString();

        Boolean acquired = redisTemplate.opsForValue()
                .setIfAbsent(lockKey, lockValue, leaseTime);

        if (Boolean.TRUE.equals(acquired)) {
            log.debug("Lock acquired for resource: {} with value: {}", resourceKey, lockValue);
            return lockValue;
        }

        log.debug("Failed to acquire lock for resource: {}", resourceKey);
        return null;
    }

    /**
     * 분산 락 해제
     */
    public boolean releaseLock(String resourceKey, String lockValue) {
        String lockKey = LOCK_PREFIX + resourceKey;

        String currentValue = redisTemplate.opsForValue().get(lockKey);
        if (lockValue.equals(currentValue)) {
            redisTemplate.delete(lockKey);
            log.debug("Lock released for resource: {}", resourceKey);
            return true;
        }

        log.warn("Failed to release lock for resource: {}. Lock value mismatch.", resourceKey);
        return false;
    }

    /**
     * 락과 함께 작업 실행
     */
    public <T> T executeWithLock(String resourceKey, Duration leaseTime,
                                 Duration waitTime, LockableOperation<T> operation) {
        String lockValue = null;
        long startTime = System.currentTimeMillis();

        try {
            // 락 획득 시도
            while (lockValue == null &&
                    (System.currentTimeMillis() - startTime) < waitTime.toMillis()) {
                lockValue = acquireLock(resourceKey, leaseTime);
                if (lockValue == null) {
                    Thread.sleep(100); // 100ms 대기 후 재시도
                }
            }

            if (lockValue == null) {
                throw new RuntimeException("Failed to acquire lock for: " + resourceKey);
            }

            // 작업 실행
            return operation.execute();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Lock acquisition interrupted", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (lockValue != null) {
                releaseLock(resourceKey, lockValue);
            }
        }
    }

    /**
     * 락 가능한 작업 인터페이스
     */
    @FunctionalInterface
    public interface LockableOperation<T> {
        T execute() throws Exception;
    }
}
