package io.springsecurity.springsecurity6x.security.core.session.impl;

import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.core.session.generator.SessionIdGenerator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Redis 기반 MFA 세션 Repository - 분산환경 완전 대응
 *
 * 핵심 특징:
 * - Redis Lua 스크립트 기반 원자적 연산
 * - 분산 클러스터 세션 ID 유니크성 보장
 * - 노드별 고유 식별자 활용
 * - 자동 충돌 해결 메커니즘
 * - 보안 강화된 세션 ID 생성
 */
@Slf4j
@Repository
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "redis")
public class RedisMfaRepository implements MfaSessionRepository {

    private final StringRedisTemplate redisTemplate;
    private final SessionIdGenerator sessionIdGenerator;

    // 상수 정의
    private static final String SESSION_PREFIX = "mfa:session:";
    private static final String COLLISION_COUNTER_KEY = "mfa:collision:counter";
    private static final String SESSION_STATS_KEY = "mfa:stats";
    private static final String COOKIE_NAME = "MFA_SID";
    private static final int MAX_COLLISION_RETRIES = 10;
    private static final int MIN_SECURITY_SCORE = 80;

    // 설정
    private Duration sessionTimeout = Duration.ofMinutes(30);

    // 통계 추적
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisions = new AtomicLong(0);

    // Lua 스크립트
    private static final String CREATE_SESSION_SCRIPT =
            "if redis.call('EXISTS', KEYS[1]) == 0 then " +
                    "    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2]) " +
                    "    return 1 " +
                    "else " +
                    "    return 0 " +
                    "end";

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        if (!isValidSessionIdFormat(sessionId)) {
            throw new IllegalArgumentException("Invalid session ID format: " + sessionId);
        }

        String redisKey = SESSION_PREFIX + sessionId;
        String sessionValue = createSessionValue(sessionId, request);

        DefaultRedisScript<Long> script = new DefaultRedisScript<>(CREATE_SESSION_SCRIPT, Long.class);
        Long result = redisTemplate.execute(script,
                Collections.singletonList(redisKey),
                sessionValue,
                String.valueOf(sessionTimeout.toMillis()));

        if (result != null && result == 1) {
            totalSessionsCreated.incrementAndGet();
            updateSessionStats();

            if (response != null) {
                setSessionCookie(response, sessionId);
            }

            log.debug("MFA session stored in Redis cluster: {} with TTL: {}", sessionId, sessionTimeout);
        } else {
            log.warn("Session ID collision detected in Redis: {}", sessionId);
            sessionCollisions.incrementAndGet();
            throw new SessionIdGenerationException("Session ID already exists in Redis cluster");
        }
    }

    @Override
    public String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request) {
        for (int attempt = 0; attempt < MAX_COLLISION_RETRIES; attempt++) {
            String sessionId = sessionIdGenerator.generate(baseId, request);

            if (isSessionIdUnique(sessionId) && getSessionIdSecurityScore(sessionId) >= MIN_SECURITY_SCORE) {
                log.debug("Generated unique session ID for Redis cluster: {} (attempt: {})",
                        sessionId, attempt + 1);
                return sessionId;
            }

            try {
                Thread.sleep(10L * (1L << Math.min(attempt, 5)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SessionIdGenerationException("Session ID generation interrupted", e);
            }
        }

        throw new SessionIdGenerationException(
                "Failed to generate unique session ID after " + MAX_COLLISION_RETRIES + " attempts");
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        String redisKey = SESSION_PREFIX + sessionId;
        return Boolean.FALSE.equals(redisTemplate.hasKey(redisKey));
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts) {
        sessionCollisions.incrementAndGet();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String newId = sessionIdGenerator.resolveCollision(originalId, attempt, request);

            if (isSessionIdUnique(newId)) {
                log.info("Session ID collision resolved: {} -> {} (attempt: {})",
                        originalId, newId, attempt + 1);
                return newId;
            }
        }

        throw new SessionIdGenerationException(
                "Failed to resolve session ID collision after " + maxAttempts + " attempts");
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        return sessionIdGenerator.isValidFormat(sessionId);
    }

    @Override
    public boolean supportsDistributedSync() {
        return true;
    }

    @Override
    public int getSessionIdSecurityScore(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return 0;
        }

        int score = 0;

        // 길이 검증 (20점)
        if (sessionId.length() >= 32) score += 20;
        else if (sessionId.length() >= 24) score += 15;
        else if (sessionId.length() >= 16) score += 10;

        // 엔트로피 검증 (30점)
        score += Math.min(30, calculateEntropy(sessionId));

        // 문자 다양성 검증 (20점)
        score += calculateCharacterDiversity(sessionId);

        // 패턴 부재 검증 (15점)
        score += calculatePatternAbsence(sessionId);

        // 예측 불가능성 검증 (15점)
        score += calculateUnpredictability(sessionId);

        return Math.min(100, score);
    }

    // 나머지 메서드들은 기존 구현과 동일...

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        String sessionId = getSessionIdFromCookie(request);
        if (sessionId == null) {
            return null;
        }

        String redisKey = SESSION_PREFIX + sessionId;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(redisKey))) {
            return sessionId;
        }

        return null;
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        String redisKey = SESSION_PREFIX + sessionId;
        redisTemplate.delete(redisKey);

        if (response != null) {
            invalidateSessionCookie(response);
        }

        log.debug("MFA session removed from Redis cluster: {}", sessionId);
    }

    @Override
    public void refreshSession(String sessionId) {
        String redisKey = SESSION_PREFIX + sessionId;
        redisTemplate.expire(redisKey, sessionTimeout);
        log.trace("Redis session TTL refreshed for: {}", sessionId);
    }

    @Override
    public boolean existsSession(String sessionId) {
        String redisKey = SESSION_PREFIX + sessionId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(redisKey));
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        this.sessionTimeout = timeout;
        log.info("Redis session timeout set to: {}", timeout);
    }

    @Override
    public String getRepositoryType() {
        return "REDIS_DISTRIBUTED";
    }

    @Override
    public SessionStats getSessionStats() {
        try {
            long activeSessions = redisTemplate.keys(SESSION_PREFIX + "*").size();
            double avgDuration = sessionTimeout.toSeconds() * 0.6;

            return new SessionStats(
                    activeSessions,
                    totalSessionsCreated.get(),
                    sessionCollisions.get(),
                    avgDuration,
                    getRepositoryType()
            );
        } catch (Exception e) {
            log.warn("Failed to get session stats from Redis", e);
            return new SessionStats(0, totalSessionsCreated.get(), sessionCollisions.get(), 0.0, getRepositoryType());
        }
    }

    // === 보안 점수 계산 유틸리티들 ===

    private int calculateEntropy(String sessionId) {
        if (sessionId.length() == 0) return 0;

        int[] charCounts = new int[256];
        for (char c : sessionId.toCharArray()) {
            charCounts[c]++;
        }

        double entropy = 0.0;
        int length = sessionId.length();

        for (int count : charCounts) {
            if (count > 0) {
                double probability = (double) count / length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        return (int) Math.min(30, entropy * 3);
    }

    private int calculateCharacterDiversity(String sessionId) {
        boolean hasLower = sessionId.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = sessionId.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = sessionId.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = sessionId.chars().anyMatch(c -> !Character.isLetterOrDigit(c));

        int diversity = 0;
        if (hasLower) diversity += 5;
        if (hasUpper) diversity += 5;
        if (hasDigit) diversity += 5;
        if (hasSpecial) diversity += 5;

        return diversity;
    }

    private int calculatePatternAbsence(String sessionId) {
        int score = 15;

        // 연속된 동일 문자 검출
        for (int i = 0; i < sessionId.length() - 2; i++) {
            if (sessionId.charAt(i) == sessionId.charAt(i + 1) &&
                    sessionId.charAt(i + 1) == sessionId.charAt(i + 2)) {
                score -= 5;
                break;
            }
        }

        // 연속된 숫자 검출
        for (int i = 0; i < sessionId.length() - 2; i++) {
            char c1 = sessionId.charAt(i);
            char c2 = sessionId.charAt(i + 1);
            char c3 = sessionId.charAt(i + 2);

            if (Character.isDigit(c1) && Character.isDigit(c2) && Character.isDigit(c3)) {
                if (c2 == c1 + 1 && c3 == c2 + 1) {
                    score -= 5;
                    break;
                }
            }
        }

        return Math.max(0, score);
    }

    private int calculateUnpredictability(String sessionId) {
        String currentTime = String.valueOf(System.currentTimeMillis());

        if (sessionId.contains(currentTime.substring(0, 8))) {
            return 5;
        }

        return 15;
    }

    // === 기존 유틸리티 메서드들 ===

    private String createSessionValue(String sessionId, HttpServletRequest request) {
        return String.format("%s|%s|%s|%d",
                sessionId,
                getClientIpAddress(request),
                request.getHeader("User-Agent") != null ?
                        request.getHeader("User-Agent").replace("|", "_") : "",
                System.currentTimeMillis());
    }

    private String getSessionIdFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .filter(StringUtils::hasText)
                .orElse(null);
    }

    private void setSessionCookie(HttpServletResponse response, String sessionId) {
        Cookie cookie = new Cookie(COOKIE_NAME, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) sessionTimeout.toSeconds());
        cookie.setAttribute("SameSite", "Strict");

        response.addCookie(cookie);
    }

    private void invalidateSessionCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);

        response.addCookie(cookie);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    private void updateSessionStats() {
        try {
            redisTemplate.opsForHash().put(SESSION_STATS_KEY,
                    "totalCreated", String.valueOf(totalSessionsCreated.get()));
            redisTemplate.opsForHash().put(SESSION_STATS_KEY,
                    "collisions", String.valueOf(sessionCollisions.get()));
            redisTemplate.opsForHash().put(SESSION_STATS_KEY,
                    "lastUpdate", String.valueOf(Instant.now().toEpochMilli()));
        } catch (Exception e) {
            log.debug("Failed to update session stats in Redis", e);
        }
    }
}
