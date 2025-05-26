package io.springsecurity.springsecurity6x.security.core.mfa.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * ContextPersistence 메트릭 설정 속성
 */
@Data
@ConfigurationProperties(prefix = "security.mfa.persistence.metrics")
public class ContextPersistenceMetricsProperties {

    /**
     * 메트릭 수집 활성화
     */
    private boolean enabled = true;

    /**
     * 메트릭 보존 기간 (시간)
     */
    private int retentionHours = 24;

    /**
     * 성능 임계값 설정
     */
    private PerformanceThresholds performance = new PerformanceThresholds();

    @Data
    public static class PerformanceThresholds {
        /**
         * 응답 시간 경고 임계값 (ms)
         */
        private long responseTimeWarningMs = 1000;

        /**
         * 응답 시간 임계 임계값 (ms)
         */
        private long responseTimeCriticalMs = 3000;

        /**
         * 오류율 경고 임계값 (%)
         */
        private double errorRateWarningPercent = 5.0;

        /**
         * 오류율 임계 임계값 (%)
         */
        private double errorRateCriticalPercent = 10.0;
    }
}
