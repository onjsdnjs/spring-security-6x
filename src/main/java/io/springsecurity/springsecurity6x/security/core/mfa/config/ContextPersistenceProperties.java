package io.springsecurity.springsecurity6x.security.core.mfa.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * ContextPersistence 설정 속성
 */
@Data
@ConfigurationProperties(prefix = "security.mfa.persistence")
public class ContextPersistenceProperties {

    /**
     * 저장 타입 (session, redis)
     */
    private PersistenceType type = PersistenceType.SESSION;

    /**
     * 세션 기반 설정
     */
    private SessionConfig session = new SessionConfig();

    /**
     * Redis 기반 설정
     */
    private RedisConfig redis = new RedisConfig();

    /**
     * 모니터링 설정
     */
    private MonitoringConfig monitoring = new MonitoringConfig();

    public enum PersistenceType {
        SESSION, REDIS
    }

    @Data
    public static class SessionConfig {
        /**
         * 세션 타임아웃 (분)
         */
        private int timeoutMinutes = 30;

        /**
         * 통계 수집 활성화
         */
        private boolean statisticsEnabled = true;

        /**
         * 최대 동시 세션 수
         */
        private int maxConcurrentSessions = 1000;
    }

    @Data
    public static class RedisConfig {
        /**
         * TTL (분)
         */
        private int ttlMinutes = 30;

        /**
         * 압축 임계값 (바이트)
         */
        private int compressionThreshold = 1024;

        /**
         * Circuit Breaker 활성화
         */
        private boolean circuitBreakerEnabled = true;

        /**
         * Circuit Breaker 오픈 지속 시간 (초)
         */
        private int circuitOpenDurationSeconds = 30;

        /**
         * 백업 키 사용
         */
        private boolean backupKeyEnabled = true;

        /**
         * 분산 락 타임아웃 (초)
         */
        private int lockTimeoutSeconds = 5;
    }

    @Data
    public static class MonitoringConfig {
        /**
         * 모니터링 활성화
         */
        private boolean enabled = true;

        /**
         * 메트릭 수집 간격 (초)
         */
        private int metricsIntervalSeconds = 60;

        /**
         * 헬스 체크 간격 (초)
         */
        private int healthCheckIntervalSeconds = 30;
    }
}
