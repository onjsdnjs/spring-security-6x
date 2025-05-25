package io.springsecurity.springsecurity6x.security.config.redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 실용적인 분산 락 서비스
 * - Lua 스크립트를 통한 원자성 보장
 * - 재진입 가능한 락 지원
 * - 데드락 방지 (TTL)
 * - 모니터링 지원
 */
@Slf4j
@RequiredArgsConstructor
public class RedisDistributedLockService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String LOCK_PREFIX = "distributed:lock:";

    // 락 획득 스크립트 (재진입 가능)
    private static final String ACQUIRE_SCRIPT =
            "if redis.call('exists', KEYS[1]) == 0 then " +
                    "  redis.call('hset', KEYS[1], 'owner', ARGV[1]) " +
                    "  redis.call('hset', KEYS[1], 'count', 1) " +
                    "  redis.call('expire', KEYS[1], ARGV[2]) " +
                    "  return 1 " +
                    "elseif redis.call('hget', KEYS[1], 'owner') == ARGV[1] then " +
                    "  redis.call('hincrby', KEYS[1], 'count', 1) " +
                    "  redis.call('expire', KEYS[1], ARGV[2]) " +
                    "  return 1 " +
                    "else " +
                    "  return 0 " +
                    "end";

    // 락 해제 스크립트
    private static final String RELEASE_SCRIPT =
            "if redis.call('hget', KEYS[1], 'owner') == ARGV[1] then " +
                    "  local count = redis.call('hincrby', KEYS[1], 'count', -1) " +
                    "  if count <= 0 then " +
                    "    return redis.call('del', KEYS[1]) " +
                    "  else " +
                    "    return 1 " +
                    "  end " +
                    "else " +
                    "  return 0 " +
                    "end";

    /**
     * 락 획득
     */
    public boolean tryLock(String resourceKey, String owner, Duration timeout) {
        String lockKey = LOCK_PREFIX + resourceKey;

        try {
            Long result = redisTemplate.execute(
                    new DefaultRedisScript<>(ACQUIRE_SCRIPT, Long.class),
                    Collections.singletonList(lockKey),
                    owner,
                    String.valueOf(timeout.getSeconds())
            );

            boolean acquired = result != null && result == 1;

            if (acquired) {
                log.debug("Lock acquired for resource: {} by owner: {}", resourceKey, owner);
            }

            return acquired;

        } catch (Exception e) {
            log.error("Failed to acquire lock for resource: {}", resourceKey, e);
            return false;
        }
    }

    /**
     * 락 해제
     */
    public boolean unlock(String resourceKey, String owner) {
        String lockKey = LOCK_PREFIX + resourceKey;

        try {
            Long result = redisTemplate.execute(
                    new DefaultRedisScript<>(RELEASE_SCRIPT, Long.class),
                    Collections.singletonList(lockKey),
                    owner
            );

            boolean released = result != null && result > 0;

            if (released) {
                log.debug("Lock released for resource: {} by owner: {}", resourceKey, owner);
            } else {
                log.warn("Failed to release lock for resource: {}. Not the owner or lock doesn't exist", resourceKey);
            }

            return released;

        } catch (Exception e) {
            log.error("Failed to release lock for resource: {}", resourceKey, e);
            return false;
        }
    }

    /**
     * 락과 함께 작업 실행
     */
    public <T> T executeWithLock(String resourceKey, Duration timeout, LockableOperation<T> operation) {
        String owner = generateLockOwner();

        if (!tryLock(resourceKey, owner, timeout)) {
            throw new LockAcquisitionException("Failed to acquire lock for: " + resourceKey);
        }

        try {
            return operation.execute();
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new RuntimeException("Operation failed", e);
        } finally {
            unlock(resourceKey, owner);
        }
    }

    /**
     * 락 획득 대기
     */
    public boolean tryLockWithWait(String resourceKey, String owner, Duration timeout, Duration waitTime) {
        long deadline = System.currentTimeMillis() + waitTime.toMillis();
        long backoff = 50; // 초기 대기 시간 (ms)

        while (System.currentTimeMillis() < deadline) {
            if (tryLock(resourceKey, owner, timeout)) {
                return true;
            }

            try {
                Thread.sleep(Math.min(backoff, deadline - System.currentTimeMillis()));
                backoff = Math.min(backoff * 2, 1000); // 최대 1초까지 증가
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        return false;
    }

    /**
     * 락 상태 확인
     */
    public LockInfo getLockInfo(String resourceKey) {
        String lockKey = LOCK_PREFIX + resourceKey;

        try {
            String owner = (String) redisTemplate.opsForHash().get(lockKey, "owner");
            if (owner == null) {
                return null;
            }

            Integer count = Integer.valueOf(
                    String.valueOf(redisTemplate.opsForHash().get(lockKey, "count"))
            );
            Long ttl = redisTemplate.getExpire(lockKey, TimeUnit.SECONDS);

            return new LockInfo(owner, count != null ? count : 0, ttl != null ? ttl : 0);

        } catch (Exception e) {
            log.error("Failed to get lock info for resource: {}", resourceKey, e);
            return null;
        }
    }

    /**
     * 락 소유자 ID 생성
     */
    private String generateLockOwner() {
        return Thread.currentThread().getName() + ":" + UUID.randomUUID().toString();
    }

    /**
     * 락 정보
     */
    public static class LockInfo {
        private final String owner;
        private final int count;
        private final long ttlSeconds;

        public LockInfo(String owner, int count, long ttlSeconds) {
            this.owner = owner;
            this.count = count;
            this.ttlSeconds = ttlSeconds;
        }

        public String getOwner() { return owner; }
        public int getCount() { return count; }
        public long getTtlSeconds() { return ttlSeconds; }
    }

    /**
     * 락 획득 가능한 작업
     */
    @FunctionalInterface
    public interface LockableOperation<T> {
        T execute() throws Exception;
    }

    /**
     * 락 획득 실패 예외
     */
    public static class LockAcquisitionException extends RuntimeException {
        public LockAcquisitionException(String message) {
            super(message);
        }
    }
}
