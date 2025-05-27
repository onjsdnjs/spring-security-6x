package io.springsecurity.springsecurity6x.security.token.store;

import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.config.redis.RedisEventPublisher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Redis 기반 RefreshToken 저장소
 *
 * 분산 환경에서의 동시성을 보장하기 위해 분산 락과 Lua 스크립트를 사용합니다.
 * AbstractRefreshTokenStore를 상속받아 Redis 저장소 관련 구현만 제공합니다.
 *
 * Redis 데이터 구조:
 * - refresh_token:{username}:{deviceId} → Hash (토큰 정보)
 * - user:devices:{username} → Sorted Set (사용자별 디바이스 관리)
 * - blacklist:token → Set (블랙리스트 토큰)
 * - blacklist:device → Set (블랙리스트 디바이스)
 *
 * @since 2024.12
 */
@Slf4j
public class RedisRefreshTokenStore extends AbstractRefreshTokenStore {

    private static final String TOKEN_KEY_PREFIX = "refresh_token:";
    private static final String USER_DEVICES_KEY_PREFIX = "user:devices:";
    private static final String BLACKLIST_TOKEN_KEY = "blacklist:token";
    private static final String BLACKLIST_DEVICE_KEY = "blacklist:device";
    private static final String LOCK_KEY_PREFIX = "token:lock:";

    private final StringRedisTemplate redisTemplate;
    private final RedisDistributedLockService lockService;
    private final RedisEventPublisher eventPublisher;

    // Lua 스크립트: 토큰 저장과 디바이스 목록 업데이트를 원자적으로 수행
    private static final String SAVE_TOKEN_SCRIPT =
            "local tokenKey = KEYS[1] " +
                    "local devicesKey = KEYS[2] " +
                    "local username = ARGV[1] " +
                    "local expiration = ARGV[2] " +
                    "local token = ARGV[3] " +
                    "local deviceId = ARGV[4] " +
                    "local ttl = ARGV[5] " +
                    "redis.call('hset', tokenKey, 'username', username, 'expiration', expiration, 'token', token) " +
                    "redis.call('expire', tokenKey, ttl) " +
                    "redis.call('zadd', devicesKey, redis.call('time')[1], deviceId) " +
                    "return 1";

    // Lua 스크립트: 토큰 제거와 디바이스 목록 업데이트를 원자적으로 수행
    private static final String REMOVE_TOKEN_SCRIPT =
            "local tokenKey = KEYS[1] " +
                    "local devicesKey = KEYS[2] " +
                    "local deviceId = ARGV[1] " +
                    "redis.call('del', tokenKey) " +
                    "redis.call('zrem', devicesKey, deviceId) " +
                    "return 1";

    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate,
                                  TokenParser tokenParser,
                                  AuthContextProperties props,
                                  RedisDistributedLockService lockService,
                                  RedisEventPublisher eventPublisher) {
        super(tokenParser, props);
        this.redisTemplate = redisTemplate;
        this.lockService = lockService;
        this.eventPublisher = eventPublisher;
    }

    @Override
    protected void doSaveToken(String username, String deviceId, String token, Instant expiration) {
        String tokenKey = TOKEN_KEY_PREFIX + deviceKey(username, deviceId);
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        long ttlSeconds = calculateTtlSeconds(expiration);

        if (ttlSeconds <= 0) {
            log.warn("Token TTL is non-positive, not saving. User: {}, deviceId: {}", username, deviceId);
            return;
        }

        // Lua 스크립트로 원자적 저장
        redisTemplate.execute(
                new DefaultRedisScript<>(SAVE_TOKEN_SCRIPT, Long.class),
                Arrays.asList(tokenKey, devicesKey),
                username,
                String.valueOf(expiration.toEpochMilli()),
                token,
                deviceId,
                String.valueOf(ttlSeconds)
        );

        // 이벤트 발행 (다른 서버에 알림)
        publishTokenSavedEvent(username, deviceId);
    }

    @Override
    protected TokenInfo doGetTokenInfo(String username, String deviceId) {
        String tokenKey = TOKEN_KEY_PREFIX + deviceKey(username, deviceId);

        Map<Object, Object> entries = redisTemplate.opsForHash().entries(tokenKey);
        if (entries.isEmpty()) {
            return null;
        }

        String storedUsername = (String) entries.get("username");
        String expirationStr = (String) entries.get("expiration");

        if (storedUsername == null || expirationStr == null) {
            return null;
        }

        Instant expiration = Instant.ofEpochMilli(Long.parseLong(expirationStr));
        return new TokenInfo(storedUsername, expiration);
    }

    @Override
    protected void doRemoveToken(String username, String deviceId) {
        String tokenKey = TOKEN_KEY_PREFIX + deviceKey(username, deviceId);
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;

        // Lua 스크립트로 원자적 제거
        redisTemplate.execute(
                new DefaultRedisScript<>(REMOVE_TOKEN_SCRIPT, Long.class),
                Arrays.asList(tokenKey, devicesKey),
                deviceId
        );

        // 이벤트 발행
        publishTokenRemovedEvent(username, deviceId);
    }

    @Override
    protected void doBlacklistToken(String token, String username, Instant expiration, String reason) {
        long ttlSeconds = calculateTtlSeconds(expiration);

        if (ttlSeconds > 0) {
            // 블랙리스트에 토큰 추가
            redisTemplate.opsForSet().add(BLACKLIST_TOKEN_KEY, token);

            // 블랙리스트 정보 저장
            String infoKey = BLACKLIST_TOKEN_KEY + ":" + token;
            redisTemplate.opsForHash().put(infoKey, "username", username);
            redisTemplate.opsForHash().put(infoKey, "reason", reason);
            redisTemplate.opsForHash().put(infoKey, "timestamp", String.valueOf(System.currentTimeMillis()));
            redisTemplate.expire(infoKey, ttlSeconds, TimeUnit.SECONDS);
        }
    }

    @Override
    protected void doBlacklistDevice(String username, String deviceId, String reason) {
        String key = deviceKey(username, deviceId);
        redisTemplate.opsForSet().add(BLACKLIST_DEVICE_KEY, key);

        // 블랙리스트 정보 저장
        String infoKey = BLACKLIST_DEVICE_KEY + ":" + key;
        redisTemplate.opsForHash().put(infoKey, "username", username);
        redisTemplate.opsForHash().put(infoKey, "deviceId", deviceId);
        redisTemplate.opsForHash().put(infoKey, "reason", reason);
        redisTemplate.opsForHash().put(infoKey, "timestamp", String.valueOf(System.currentTimeMillis()));
    }

    @Override
    protected Iterable<String> doGetUserDevices(String username) {
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        Set<String> devices = redisTemplate.opsForZSet().range(devicesKey, 0, -1);
        return devices != null ? devices : Collections.emptySet();
    }

    @Override
    protected int doGetUserDeviceCount(String username) {
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        Long count = redisTemplate.opsForZSet().zCard(devicesKey);
        return count != null ? count.intValue() : 0;
    }

    @Override
    protected String doGetOldestDevice(String username) {
        String devicesKey = USER_DEVICES_KEY_PREFIX + username;
        Set<String> oldest = redisTemplate.opsForZSet().range(devicesKey, 0, 0);
        return (oldest != null && !oldest.isEmpty()) ? oldest.iterator().next() : null;
    }

    @Override
    public boolean isBlacklisted(String token) {
        if (token == null) {
            return false;
        }

        // 토큰 블랙리스트 확인
        if (Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(BLACKLIST_TOKEN_KEY, token))) {
            return true;
        }

        // 디바이스 블랙리스트 확인
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                return false;
            }

            String deviceKey = deviceKey(subject, deviceId);
            return Boolean.TRUE.equals(
                    redisTemplate.opsForSet().isMember(BLACKLIST_DEVICE_KEY, deviceKey)
            );

        } catch (JwtException e) {
            log.trace("JWT parsing failed during isBlacklisted check for token: {}", token, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during isBlacklisted check. Token: {}", token, e);
            return false;
        }
    }

    /**
     * 동시 로그인 정책 처리 (분산 락 사용)
     * AbstractRefreshTokenStore의 save 메서드에서 호출되는 handleConcurrentLoginPolicy를 위해
     * 오버라이드하여 분산 락으로 보호
     */
    @Override
    public void save(String refreshToken, String username) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        Objects.requireNonNull(username, "username cannot be null");

        String lockKey = LOCK_KEY_PREFIX + username;

        try {
            // 분산 락으로 동시성 제어
            lockService.executeWithLock(lockKey, Duration.ofSeconds(5), () -> {
                super.save(refreshToken, username);
                return null;
            });
        } catch (RedisDistributedLockService.LockAcquisitionException e) {
            log.error("Failed to acquire lock for saving token. User: {}", username, e);
            throw new RuntimeException("Token save failed due to lock acquisition failure", e);
        }
    }

    /**
     * TTL 계산
     */
    private long calculateTtlSeconds(Instant expiration) {
        return Math.max(0, expiration.toEpochMilli() / 1000 - Instant.now().toEpochMilli() / 1000);
    }

    /**
     * 토큰 저장 이벤트 발행
     */
    private void publishTokenSavedEvent(String username, String deviceId) {
        Map<String, Object> data = new HashMap<>();
        data.put("deviceId", deviceId);
        eventPublisher.publishAuthenticationEvent("TOKEN_SAVED", username, data);
    }

    /**
     * 토큰 제거 이벤트 발행
     */
    private void publishTokenRemovedEvent(String username, String deviceId) {
        Map<String, Object> data = new HashMap<>();
        data.put("deviceId", deviceId);
        eventPublisher.publishAuthenticationEvent("TOKEN_REMOVED", username, data);
    }
}