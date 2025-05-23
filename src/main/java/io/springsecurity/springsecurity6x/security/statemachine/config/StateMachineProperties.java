package io.springsecurity.springsecurity6x.security.statemachine.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * State Machine 관련 설정 속성
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "security.statemachine.mfa")
public class StateMachineProperties {

    /**
     * State Machine 자동 시작 여부
     */
    private boolean autoStartup = false;

    /**
     * State Machine 영속성 사용 여부
     */
    private boolean enablePersistence = true;

    /**
     * State Machine 컨텍스트 TTL (분)
     */
    private int contextTtlMinutes = 30;

    /**
     * 최대 동시 State Machine 인스턴스 수
     */
    private int maxConcurrentMachines = 1000;

    /**
     * State Machine 이벤트 로깅 활성화
     */
    private boolean enableEventLogging = true;

    /**
     * State Machine 메트릭 수집 활성화
     */
    private boolean enableMetrics = true;

    /**
     * Redis 설정 (영속성용)
     */
    private RedisConfig redis = new RedisConfig();

    @Data
    public static class RedisConfig {
        private boolean enabled = false;
        private String keyPrefix = "mfa:statemachine:";
        private int connectionTimeout = 2000;
        private int readTimeout = 5000;
    }
}