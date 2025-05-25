package io.springsecurity.springsecurity6x.security.statemachine.monitoring;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * MFA State Machine 모니터링 및 메트릭 수집
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineMonitoring implements HealthIndicator {

    private final MeterRegistry meterRegistry;

    // 메트릭 저장소
    private final Map<String, AtomicLong> stateCounters = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> eventCounters = new ConcurrentHashMap<>();
    private final Map<String, Timer> transitionTimers = new ConcurrentHashMap<>();

    // Gauge를 위한 상태별 카운트 저장
    private final Map<MfaState, AtomicLong> currentStateDistribution = new ConcurrentHashMap<>();

    // 상태 통계
    private volatile long totalTransitions = 0;
    private volatile long failedTransitions = 0;
    private volatile long activeSessions = 0;

    // 임계값
    private static final double ERROR_RATE_THRESHOLD = 0.1; // 10%
    private static final long SLOW_TRANSITION_THRESHOLD_MS = 1000; // 1초

    /**
     * 상태 전이 기록
     */
    @EventListener
    public void onStateChange(MfaStateChangeEvent event) {
        String transitionKey = event.getFromState() + "_to_" + event.getToState();

        // 카운터 증가
        Counter.builder("mfa.state.transition")
                .tag("from", event.getFromState().name())
                .tag("to", event.getToState().name())
                .tag("event", event.getEvent().name())
                .register(meterRegistry)
                .increment();

        // 타이머 기록
        Timer timer = transitionTimers.computeIfAbsent(transitionKey, k ->
                Timer.builder("mfa.state.transition.duration")
                        .tag("transition", transitionKey)
                        .publishPercentiles(0.5, 0.95, 0.99)
                        .register(meterRegistry)
        );

        timer.record(event.getDuration());

        // 통계 업데이트
        totalTransitions++;

        // 느린 전이 감지
        if (event.getDuration().toMillis() > SLOW_TRANSITION_THRESHOLD_MS) {
            log.warn("Slow state transition detected: {} ({} ms)",
                    transitionKey, event.getDuration().toMillis());
        }
    }

    /**
     * 이벤트 처리 실패 기록
     */
    @EventListener
    public void onEventFailure(MfaEventFailureEvent event) {
        failedTransitions++;

        Counter.builder("mfa.event.failure")
                .tag("event", event.getEvent().name())
                .tag("error", event.getError().getClass().getSimpleName())
                .register(meterRegistry)
                .increment();

        // 임계값 초과 시 알림
        double errorRate = (double) failedTransitions / totalTransitions;
        if (errorRate > ERROR_RATE_THRESHOLD) {
            log.error("MFA error rate exceeded threshold: {}", String.format("%.2f%%", errorRate * 100));
            // 알림 시스템 호출
            sendAlert("MFA_HIGH_ERROR_RATE", errorRate);
        }
    }

    /**
     * 활성 세션 수 업데이트
     */
    public void updateActiveSessions(long count) {
        this.activeSessions = count;

        meterRegistry.gauge("mfa.sessions.active", count);
    }

    /**
     * 헬스 체크
     */
    @Override
    public Health health() {
        Map<String, Object> details = new HashMap<>();

        // 기본 통계
        details.put("totalTransitions", totalTransitions);
        details.put("failedTransitions", failedTransitions);
        details.put("activeSessions", activeSessions);

        // 에러율 계산
        double errorRate = totalTransitions > 0 ?
                (double) failedTransitions / totalTransitions : 0;
        details.put("errorRate", String.format("%.2f%%", errorRate * 100));

        // 상태별 분포
        Map<String, Long> stateDistribution = calculateStateDistribution();
        details.put("stateDistribution", stateDistribution);

        // 헬스 상태 판단
        Health.Builder builder = errorRate > ERROR_RATE_THRESHOLD ?
                Health.down() : Health.up();

        return builder.withDetails(details).build();
    }

    /**
     * 주기적 메트릭 수집 (1분마다)
     */
    @Scheduled(fixedDelay = 60000)
    public void collectMetrics() {
        // 상태별 세션 수 집계
        Map<MfaState, Long> stateCount = getCurrentStateDistribution();

        // 현재 상태 분포를 AtomicLong에 업데이트
        stateCount.forEach((state, count) -> {
            AtomicLong counter = currentStateDistribution.get(state);
            if (counter != null) {
                counter.set(count);
            }
        });

        // 평균 전이 시간 계산
        transitionTimers.forEach((transition, timer) -> {
            double avgTime = timer.mean(TimeUnit.MILLISECONDS);
            if (avgTime > SLOW_TRANSITION_THRESHOLD_MS) {
                log.info("Transition {} average time: {} ms", transition, avgTime);
            }
        });
    }

    /**
     * 상태 분포 계산
     */
    private Map<String, Long> calculateStateDistribution() {
        Map<String, Long> distribution = new HashMap<>();

        for (MfaState state : MfaState.values()) {
            long count = stateCounters.getOrDefault(state.name(), new AtomicLong(0)).get();
            if (count > 0) {
                distribution.put(state.name(), count);
            }
        }

        return distribution;
    }

    /**
     * 현재 상태 분포 조회 (실시간)
     */
    private Map<MfaState, Long> getCurrentStateDistribution() {
        // 실제 구현에서는 Redis나 DB에서 조회
        Map<MfaState, Long> distribution = new HashMap<>();

        // 예시 데이터
        distribution.put(MfaState.AWAITING_FACTOR_SELECTION, 150L);
        distribution.put(MfaState.FACTOR_VERIFICATION_PENDING, 50L);
        distribution.put(MfaState.MFA_SUCCESSFUL, 1000L);

        return distribution;
    }

    /**
     * 알림 전송
     */
    private void sendAlert(String alertType, Object value) {
        // 실제 구현에서는 알림 시스템 연동
        log.error("ALERT [{}]: {}", alertType, value);

        // Slack, Email, PagerDuty 등으로 알림 전송
        CompletableFuture.runAsync(() -> {
            try {
                // 알림 서비스 호출
                log.info("Sending alert: {} = {}", alertType, value);
            } catch (Exception e) {
                log.error("Failed to send alert", e);
            }
        });
    }

    /**
     * 성능 분석 리포트 생성
     */
    public PerformanceReport generatePerformanceReport() {
        PerformanceReport report = new PerformanceReport();

        // 전체 통계
        report.setTotalTransitions(totalTransitions);
        report.setFailedTransitions(failedTransitions);
        report.setSuccessRate(calculateSuccessRate());

        // 상태별 통계
        transitionTimers.forEach((transition, timer) -> {
            TransitionStats stats = new TransitionStats();
            stats.setTransition(transition);
            stats.setCount(timer.count());
            stats.setAvgDuration(timer.mean(TimeUnit.MILLISECONDS));
            stats.setMaxDuration(timer.max(TimeUnit.MILLISECONDS));
            stats.setP95Duration(timer.percentile(0.95, TimeUnit.MILLISECONDS));

            report.addTransitionStats(stats);
        });

        // 병목 구간 식별
        report.setBottlenecks(identifyBottlenecks());

        return report;
    }

    /**
     * 병목 구간 식별
     */
    private List<String> identifyBottlenecks() {
        List<String> bottlenecks = new ArrayList<>();

        transitionTimers.forEach((transition, timer) -> {
            double p95 = timer.percentile(0.95, TimeUnit.MILLISECONDS);
            if (p95 > SLOW_TRANSITION_THRESHOLD_MS * 2) {
                bottlenecks.add(String.format("%s (P95: %.0f ms)", transition, p95));
            }
        });

        return bottlenecks;
    }

    /**
     * 성공률 계산
     */
    private double calculateSuccessRate() {
        return totalTransitions > 0 ?
                1.0 - ((double) failedTransitions / totalTransitions) : 1.0;
    }

    /**
     * 커스텀 메트릭 등록
     */
    @PostConstruct
    public void registerCustomMetrics() {
        // 동시 세션 수
        Gauge.builder("mfa.sessions.concurrent", this, MfaStateMachineMonitoring::getActiveSessions)
                .description("Number of concurrent MFA sessions")
                .register(meterRegistry);

        // 성공률
        Gauge.builder("mfa.success.rate", this, MfaStateMachineMonitoring::calculateSuccessRate)
                .description("MFA success rate")
                .register(meterRegistry);

        // 평균 완료 시간
        Gauge.builder("mfa.completion.time.avg", this, MfaStateMachineMonitoring::getAverageCompletionTime)
                .description("Average MFA completion time in seconds")
                .baseUnit("seconds")
                .register(meterRegistry);

        // 상태별 세션 수 Gauge 등록
        for (MfaState state : MfaState.values()) {
            currentStateDistribution.put(state, new AtomicLong(0));

            Gauge.builder("mfa.sessions.by.state", currentStateDistribution.get(state), AtomicLong::get)
                    .tag("state", state.name())
                    .description("Number of sessions in state " + state.name())
                    .register(meterRegistry);
        }
    }

    /**
     * 평균 완료 시간 계산
     */
    private double getAverageCompletionTime() {
        Timer completionTimer = transitionTimers.get("START_MFA_to_MFA_SUCCESSFUL");
        return completionTimer != null ?
                completionTimer.mean(TimeUnit.SECONDS) : 0.0;
    }

    /**
     * 활성 세션 수 조회
     */
    private long getActiveSessions() {
        return activeSessions;
    }

    /**
     * 이벤트 클래스들
     */
    @Getter
    public static class MfaStateChangeEvent {
        private final String sessionId;
        private final MfaState fromState;
        private final MfaState toState;
        private final MfaEvent event;
        private final Duration duration;
        private final LocalDateTime timestamp;

        public MfaStateChangeEvent(String sessionId, MfaState fromState, MfaState toState,
                                   MfaEvent event, Duration duration) {
            this.sessionId = sessionId;
            this.fromState = fromState;
            this.toState = toState;
            this.event = event;
            this.duration = duration;
            this.timestamp = LocalDateTime.now();
        }
    }

    @Getter
    public static class MfaEventFailureEvent {
        private final String sessionId;
        private final MfaEvent event;
        private final Exception error;
        private final LocalDateTime timestamp;

        public MfaEventFailureEvent(String sessionId, MfaEvent event, Exception error) {
            this.sessionId = sessionId;
            this.event = event;
            this.error = error;
            this.timestamp = LocalDateTime.now();
        }
    }

    /**
     * 성능 리포트
     */
    @Data
    public static class PerformanceReport {
        private long totalTransitions;
        private long failedTransitions;
        private double successRate;
        private List<TransitionStats> transitionStats = new ArrayList<>();
        private List<String> bottlenecks = new ArrayList<>();
        private LocalDateTime generatedAt = LocalDateTime.now();

        public void addTransitionStats(TransitionStats stats) {
            transitionStats.add(stats);
        }
    }

    /**
     * 전이 통계
     */
    @Data
    public static class TransitionStats {
        private String transition;
        private long count;
        private double avgDuration;
        private double maxDuration;
        private double p95Duration;
    }

    /**
     * 알림
     */
    @Data
    @AllArgsConstructor
    public static class Alert {
        private String type;
        private Object value;
        private Severity severity;
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
}