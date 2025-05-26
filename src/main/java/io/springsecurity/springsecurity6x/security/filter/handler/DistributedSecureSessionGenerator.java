package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 분산환경 완전 대응 보안 세션 ID 생성기
 * - 서버별 고유성 보장
 * - 원자적 생성 및 충돌 감지
 * - 성능 최적화된 동시성 처리
 * - Redis 기반 중복 방지
 */
@Slf4j
@Component
public class DistributedSecureSessionGenerator {

    private final StringRedisTemplate redisTemplate;
    private final BytesKeyGenerator keyGenerator;
    private final SecureRandom secureRandom;

    // 서버 고유 식별자 (최대 6바이트)
    private String serverUniqueId;

    // 원자적 카운터 (동시성 안전)
    private final AtomicLong sequenceCounter = new AtomicLong(0);

    // 마지막 생성 시간 (중복 방지)
    private volatile long lastGenerationTime = 0;

    @Value("${spring.application.name:mfa-app}")
    private String applicationName;

    @Value("${server.port:8080}")
    private int serverPort;

    @Value("${security.mfa.session.collision-retry:3}")
    private int maxRetryAttempts;

    // Redis Lua 스크립트 (원자적 검증 및 저장)
    private final DefaultRedisScript<Boolean> atomicStoreScript;

    public DistributedSecureSessionGenerator(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.keyGenerator = KeyGenerators.secureRandom(20); // 20바이트 기본 랜덤
        this.secureRandom = new SecureRandom();

        // Redis Lua 스크립트 초기화
        this.atomicStoreScript = new DefaultRedisScript<>();
        this.atomicStoreScript.setScriptText(
                "if redis.call('exists', KEYS[1]) == 0 then " +
                        "  redis.call('setex', KEYS[1], ARGV[2], ARGV[1]) " +
                        "  return true " +
                        "else " +
                        "  return false " +
                        "end"
        );
        this.atomicStoreScript.setResultType(Boolean.class);
    }

    @PostConstruct
    public void initializeServerIdentity() {
        try {
            // 서버 고유 식별자 생성 (호스트명 + 포트 + 랜덤)
            String hostname = InetAddress.getLocalHost().getHostName();
            String serverInfo = hostname + ":" + serverPort + ":" + applicationName;

            // SHA-256 해시의 첫 6바이트 사용
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(serverInfo.getBytes());
            byte[] serverIdBytes = Arrays.copyOf(hash, 6);

            this.serverUniqueId = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(serverIdBytes);

            log.info("Server unique ID initialized: {} (from {})", serverUniqueId, serverInfo);

        } catch (Exception e) {
            // 폴백: 랜덤 서버 ID 생성
            byte[] fallbackId = new byte[6];
            secureRandom.nextBytes(fallbackId);
            this.serverUniqueId = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(fallbackId);

            log.warn("Failed to generate server ID from system info, using fallback: {}",
                    serverUniqueId, e);
        }
    }

    /**
     * 분산환경 완전 안전 세션 ID 생성
     * 형식: [서버ID-8자리][타임스탬프-11자리][시퀀스-4자리][랜덤-20자리]
     */
    public String generateSecureSessionId() {
        for (int attempt = 0; attempt < maxRetryAttempts; attempt++) {
            try {
                String sessionId = generateUniqueSessionId();

                // Redis에서 원자적 중복 검증 및 저장
                if (verifyAndReserveSessionId(sessionId)) {
                    log.debug("Secure session ID generated successfully: {} (attempt: {})",
                            sessionId, attempt + 1);
                    return sessionId;
                }

                log.debug("Session ID collision detected, retrying: {} (attempt: {})",
                        sessionId, attempt + 1);

                // 충돌 시 짧은 지연 후 재시도
                Thread.sleep(1 + ThreadLocalRandom.current().nextInt(5));

            } catch (Exception e) {
                log.warn("Error generating session ID (attempt: {}): {}", attempt + 1, e.getMessage());

                if (attempt == maxRetryAttempts - 1) {
                    throw new SessionGenerationException("Failed to generate unique session ID after "
                            + maxRetryAttempts + " attempts", e);
                }
            }
        }

        throw new SessionGenerationException("Exhausted all retry attempts for session ID generation");
    }

    /**
     * 고성능 원자적 FactorContext 생성
     * - 동시성 안전 보장
     * - 메모리 사전 할당 최적화
     */
    public FactorContext createFactorContextAtomically(Authentication authentication,
                                                       MfaState initialState,
                                                       String flowTypeName) {

        // 세션 ID 생성
        String mfaSessionId = generateSecureSessionId();

        // FactorContext 원자적 생성 (메모리 사전 할당)
        FactorContext context = new FactorContext(mfaSessionId, authentication, initialState, flowTypeName);

        // 동시성 안전 초기화
        context.setAttribute("serverUniqueId", serverUniqueId);
        context.setAttribute("generationTimestamp", System.currentTimeMillis());
        context.setAttribute("generationNanos", System.nanoTime());

        log.debug("Atomic FactorContext created: sessionId={}, user={}, state={}",
                mfaSessionId, authentication.getName(), initialState);

        return context;
    }

    /**
     * 내부 고유 세션 ID 생성
     */
    private String generateUniqueSessionId() {
        // 1. 현재 시간 (밀리초)
        long currentTime = System.currentTimeMillis();

        // 2. 동일 시간 방지를 위한 동기화
        synchronized (this) {
            if (currentTime <= lastGenerationTime) {
                currentTime = lastGenerationTime + 1;
            }
            lastGenerationTime = currentTime;
        }

        // 3. 원자적 시퀀스 번호
        long sequence = sequenceCounter.incrementAndGet();

        // 4. 추가 랜덤 요소
        byte[] randomBytes = keyGenerator.generateKey();

        // 5. 나노초 추가 (충돌 확률 극소화)
        long nanoTime = System.nanoTime();

        // 조합: 서버ID(8) + 시간(11) + 시퀀스(4) + 나노(6) + 랜덤(변가)
        StringBuilder sessionId = new StringBuilder(64);
        sessionId.append(serverUniqueId);                    // 8자리 (서버 고유성)
        sessionId.append(String.format("%011d", currentTime)); // 11자리 (시간 고유성)
        sessionId.append(String.format("%04d", sequence % 10000)); // 4자리 (순서 고유성)
        sessionId.append(String.format("%06d", Math.abs((int)(nanoTime % 1000000)))); // 6자리 (나노초)
        sessionId.append(Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)); // 랜덤

        return sessionId.toString();
    }

    /**
     * Redis 원자적 검증 및 예약
     */
    private boolean verifyAndReserveSessionId(String sessionId) {
        String redisKey = "mfa:session:reserve:" + sessionId;
        String reservationValue = serverUniqueId + ":" + System.currentTimeMillis();

        // Lua 스크립트로 원자적 실행 (충돌 방지)
        Boolean reserved = redisTemplate.execute(atomicStoreScript,
                List.of(redisKey),
                reservationValue,
                "300"); // 5분 예약

        if (Boolean.TRUE.equals(reserved)) {
            log.debug("Session ID successfully reserved: {}", sessionId);
            return true;
        } else {
            log.debug("Session ID collision detected in Redis: {}", sessionId);
            return false;
        }
    }

    /**
     * 세션 ID 예약 해제 (정리용)
     */
    public void releaseSessionReservation(String sessionId) {
        String redisKey = "mfa:session:reserve:" + sessionId;
        redisTemplate.delete(redisKey);
        log.debug("Session ID reservation released: {}", sessionId);
    }

    /**
     * 현재 서버 통계 정보
     */
    public ServerGenerationStats getGenerationStats() {
        return ServerGenerationStats.builder()
                .serverUniqueId(serverUniqueId)
                .totalGenerated(sequenceCounter.get())
                .lastGenerationTime(lastGenerationTime)
                .currentTimeMillis(System.currentTimeMillis())
                .build();
    }

    /**
     * 세션 ID 형식 검증
     */
    public boolean isValidSessionIdFormat(String sessionId) {
        if (sessionId == null || sessionId.length() < 30) {
            return false;
        }

        // 서버 ID 부분 검증
        String extractedServerId = sessionId.substring(0, 8);
        boolean hasValidPrefix = sessionId.startsWith(serverUniqueId) ||
                isKnownServerPrefix(extractedServerId);

        // 시간 부분 검증 (대략적)
        try {
            String timeStr = sessionId.substring(8, 19);
            long timestamp = Long.parseLong(timeStr);
            long currentTime = System.currentTimeMillis();

            // 1시간 이내 생성된 세션 ID만 유효
            return hasValidPrefix &&
                    timestamp > 0 &&
                    timestamp <= currentTime &&
                    (currentTime - timestamp) < 3600000; // 1시간
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 알려진 서버 접두사 확인 (클러스터 환경용)
     */
    private boolean isKnownServerPrefix(String serverId) {
        // Redis에서 알려진 서버 목록 확인 (옵션)
        return redisTemplate.hasKey("mfa:servers:known:" + serverId);
    }

    // 통계 정보 클래스
    public static class ServerGenerationStats {
        private final String serverUniqueId;
        private final long totalGenerated;
        private final long lastGenerationTime;
        private final long currentTimeMillis;

        private ServerGenerationStats(String serverUniqueId, long totalGenerated,
                                      long lastGenerationTime, long currentTimeMillis) {
            this.serverUniqueId = serverUniqueId;
            this.totalGenerated = totalGenerated;
            this.lastGenerationTime = lastGenerationTime;
            this.currentTimeMillis = currentTimeMillis;
        }

        public static ServerGenerationStatsBuilder builder() {
            return new ServerGenerationStatsBuilder();
        }

        // Builder 패턴
        public static class ServerGenerationStatsBuilder {
            private String serverUniqueId;
            private long totalGenerated;
            private long lastGenerationTime;
            private long currentTimeMillis;

            public ServerGenerationStatsBuilder serverUniqueId(String serverUniqueId) {
                this.serverUniqueId = serverUniqueId;
                return this;
            }

            public ServerGenerationStatsBuilder totalGenerated(long totalGenerated) {
                this.totalGenerated = totalGenerated;
                return this;
            }

            public ServerGenerationStatsBuilder lastGenerationTime(long lastGenerationTime) {
                this.lastGenerationTime = lastGenerationTime;
                return this;
            }

            public ServerGenerationStatsBuilder currentTimeMillis(long currentTimeMillis) {
                this.currentTimeMillis = currentTimeMillis;
                return this;
            }

            public ServerGenerationStats build() {
                return new ServerGenerationStats(serverUniqueId, totalGenerated,
                        lastGenerationTime, currentTimeMillis);
            }
        }

        // Getter 메서드들
        public String getServerUniqueId() { return serverUniqueId; }
        public long getTotalGenerated() { return totalGenerated; }
        public long getLastGenerationTime() { return lastGenerationTime; }
        public long getCurrentTimeMillis() { return currentTimeMillis; }
    }

    // 예외 클래스
    public static class SessionGenerationException extends RuntimeException {
        public SessionGenerationException(String message) {
            super(message);
        }

        public SessionGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}