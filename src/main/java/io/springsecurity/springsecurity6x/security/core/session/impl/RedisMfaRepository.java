package io.springsecurity.springsecurity6x.security.core.session.impl;

import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Arrays;

@Slf4j
@Repository
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "redis")
public class RedisMfaRepository implements MfaSessionRepository {

    private final StringRedisTemplate redisTemplate;

    private static final String SESSION_PREFIX = "mfa:session:";
    private static final String COOKIE_NAME = "MFA_SID";
    private Duration sessionTimeout = Duration.ofMinutes(30);

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        String redisKey = SESSION_PREFIX + sessionId;
        String sessionValue = createSessionValue(sessionId, request);

        // Redis에 TTL과 함께 저장
        redisTemplate.opsForValue().set(redisKey, sessionValue, sessionTimeout);

        // 쿠키 설정 (response가 있는 경우)
        if (response != null) {
            setSessionCookie(response, sessionId);
        }

        log.debug("MFA session stored in Redis: {} with TTL: {}", sessionId, sessionTimeout);
    }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        // 쿠키에서 세션 ID 추출
        String sessionId = getSessionIdFromCookie(request);
        if (sessionId == null) {
            return null;
        }

        // Redis에서 존재 여부 확인
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

        // 쿠키 무효화 (response가 있는 경우)
        if (response != null) {
            invalidateSessionCookie(response);
        }

        log.debug("MFA session removed from Redis: {}", sessionId);
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
        return "REDIS";
    }

    // === Redis 전용 유틸리티 메서드들 ===

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
}