package io.springsecurity.springsecurity6x.security.statemachine.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * State Machine 설정 프로퍼티
 */
@Data
@ConfigurationProperties(prefix = "security.statemachine")
public class StateMachineProperties {

    /**
     * State Machine 활성화 여부
     */
    private boolean enabled = true;

    /**
     * 영속화 설정
     */
    @NestedConfigurationProperty
    private PersistenceProperties persistence = new PersistenceProperties();

    /**
     * 캐시 설정
     */
    @NestedConfigurationProperty
    private CacheProperties cache = new CacheProperties();

    /**
     * 이벤트 설정
     */
    @NestedConfigurationProperty
    private EventsProperties events = new EventsProperties();

    /**
     * MFA 관련 설정
     */
    @NestedConfigurationProperty
    private MfaProperties mfa = new MfaProperties();

    /**
     * Redis 설정
     */
    @NestedConfigurationProperty
    private RedisProperties redis = new RedisProperties();

    /**
     * 분산 락 설정
     */
    @NestedConfigurationProperty
    private DistributedLockProperties distributedLock = new DistributedLockProperties();

    /**
     * 영속화 설정
     */
    @Data
    public static class PersistenceProperties {
        /**
         * 영속화 타입 (memory, redis, hybrid)
         */
        private String type = "memory";

        /**
         * Fallback 활성화
         */
        private boolean enableFallback = true;

        /**
         * TTL (분)
         */
        private Integer ttlMinutes = 30;
    }

    /**
     * 캐시 설정
     */
    @Data
    public static class CacheProperties {
        /**
         * 최대 캐시 크기
         */
        private int maxSize = 1000;

        /**
         * 캐시 TTL (분)
         */
        private int ttlMinutes = 5;
    }

    /**
     * 이벤트 설정
     */
    @Data
    public static class EventsProperties {
        /**
         * 이벤트 발행 활성화
         */
        private boolean enabled = true;

        /**
         * 이벤트 타입 (local, redis, kafka)
         */
        private String type = "local";
    }

    /**
     * MFA 설정
     */
    @Data
    public static class MfaProperties {
        /**
         * 메트릭 수집 활성화
         */
        private boolean enableMetrics = true;

        /**
         * 최대 재시도 횟수
         */
        private Integer maxRetries = 3;

        /**
         * 세션 타임아웃 (분)
         */
        private Integer sessionTimeoutMinutes = 30;
    }

    /**
     * Redis 설정
     */
    @Data
    public static class RedisProperties {
        /**
         * Redis 사용 여부
         */
        private boolean enabled = false;

        /**
         * TTL (분)
         */
        private Integer ttlMinutes = 30;

        /**
         * 키 프리픽스
         */
        private String keyPrefix = "mfa:statemachine:";
    }

    /**
     * 분산 락 설정
     */
    @Data
    public static class DistributedLockProperties {
        /**
         * 분산 락 활성화
         */
        private boolean enabled = true;

        /**
         * 락 타임아웃 (초)
         */
        private int timeoutSeconds = 10;

        /**
         * 최대 재시도 횟수
         */
        private int maxRetryAttempts = 3;
    }
}