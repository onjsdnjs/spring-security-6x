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
     * 영속화 활성화 여부
     */
    private boolean enablePersistence = true;

    /**
     * 컨텍스트 TTL (분)
     */
    private Integer contextTtlMinutes = 30;

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
}