package io.springsecurity.springsecurity6x.security.statemachine.core.event;

import io.springsecurity.springsecurity6x.security.statemachine.core.event.MfaStateMachineEvents.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * 비동기 이벤트 리스너
 * @EventListener 와 @Async를 활용한 논블로킹 처리
 */
@Slf4j
@Component
public class MfaAsyncEventListener {

    private final RedisTemplate<String, String> redisTemplate;

    public MfaAsyncEventListener(@Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 상태 변경 이벤트 처리
     */
    @Async("mfaEventExecutor")
    @EventListener
    public void handleStateChange(StateChangeEvent event) {
        try {
            // 로컬 처리
            log.info("State changed from {} to {} for session: {}",
                    event.getFromState(), event.getToState(), event.getSessionId());

            // Redis 발행 (비동기)
            CompletableFuture.runAsync(() -> publishToRedis(event));

        } catch (Exception e) {
            log.error("Failed to handle state change event", e);
        }
    }

    /**
     * 에러 이벤트 처리
     */
    @Async("mfaEventExecutor")
    @EventListener
    public void handleError(ErrorEvent event) {
        try {
            log.error("MFA error for session {}: {} - {}",
                    event.getSessionId(),
                    event.getErrorType(),
                    event.getError().getMessage());

            // 알림 처리
            if (shouldAlert(event)) {
                CompletableFuture.runAsync(() -> sendAlert(event));
            }

            // Redis 발행
            CompletableFuture.runAsync(() -> publishErrorToRedis(event));

        } catch (Exception e) {
            log.error("Failed to handle error event", e);
        }
    }

    /**
     * 커스텀 이벤트 처리
     */
    @Async("mfaEventExecutor")
    @EventListener
    public void handleCustomEvent(CustomEvent event) {
        try {
            log.debug("Custom event: {} with payload: {}",
                    event.getEventType(), event.getPayload());

            // 이벤트 타입별 처리
            switch (event.getEventType()) {
                case "SESSION_CLEANUP":
                    handleSessionCleanup(event.getPayload());
                    break;
                case "METRIC_COLLECTION":
                    handleMetricCollection(event.getPayload());
                    break;
                default:
                    log.debug("Unhandled custom event type: {}", event.getEventType());
            }

        } catch (Exception e) {
            log.error("Failed to handle custom event", e);
        }
    }

    /**
     * 트랜잭션 커밋 후 중요 이벤트 처리
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async("mfaEventExecutor")
    public void handleCriticalStateChange(StateChangeEvent event) {
        if (event.getToState().isTerminal()) {
            log.info("Critical state change committed: {} for session: {}",
                    event.getToState(), event.getSessionId());

            // 감사 로그
            auditLog(event);
        }
    }

    /**
     * Redis에 상태 변경 이벤트 발행
     */
    private void publishToRedis(StateChangeEvent event) {
        if (redisTemplate == null) return;

        try {
            Map<String, Object> message = new HashMap<>();
            message.put("type", "STATE_CHANGE");
            message.put("sessionId", event.getSessionId());
            message.put("fromState", event.getFromState() != null ? event.getFromState().name() : null);
            message.put("toState", event.getToState().name());
            message.put("event", event.getEvent().name());
            message.put("timestamp", event.getOccurredAt().toString());  // occurredAt 사용
            if (event.getDuration() != null) {
                message.put("duration", event.getDuration().toMillis());
            }

            redisTemplate.convertAndSend("mfa:events:state-change", message);

        } catch (Exception e) {
            log.warn("Failed to publish to Redis", e);
        }
    }

    /**
     * Redis에 에러 이벤트 발행
     */
    private void publishErrorToRedis(ErrorEvent event) {
        if (redisTemplate == null) return;

        try {
            Map<String, Object> message = new HashMap<>();
            message.put("type", "ERROR");
            message.put("sessionId", event.getSessionId());
            message.put("currentState", event.getCurrentState().name());
            message.put("event", event.getEvent() != null ? event.getEvent().name() : null);
            message.put("errorType", event.getErrorType().name());
            message.put("error", event.getError().getClass().getSimpleName());
            message.put("message", event.getError().getMessage());
            message.put("timestamp", event.getOccurredAt().toString());

            redisTemplate.convertAndSend("mfa:events:error", message);

        } catch (Exception e) {
            log.warn("Failed to publish error to Redis", e);
        }
    }

    /**
     * 알림이 필요한지 판단
     */
    private boolean shouldAlert(ErrorEvent event) {
        return event.getErrorType() == ErrorEvent.ErrorType.SECURITY ||
                event.getErrorType() == ErrorEvent.ErrorType.LIMIT_EXCEEDED;
    }

    /**
     * 알림 전송
     */
    private void sendAlert(ErrorEvent event) {
        log.error("ALERT: MFA error for session {} - Type: {}, Error: {}",
                event.getSessionId(),
                event.getErrorType(),
                event.getError().getMessage());
        // TODO: 실제 알림 시스템 연동
    }

    /**
     * 세션 정리 처리
     */
    private void handleSessionCleanup(Object payload) {
        log.info("Processing session cleanup: {}", payload);
        // TODO: 세션 정리 로직
    }

    /**
     * 메트릭 수집 처리
     */
    private void handleMetricCollection(Object payload) {
        log.debug("Processing metric collection: {}", payload);
        // TODO: 메트릭 수집 로직
    }

    /**
     * 감사 로그
     */
    private void auditLog(StateChangeEvent event) {
        log.info("AUDIT: MFA {} for session {} at {}",
                event.getToState(),
                event.getSessionId(),
                event.getOccurredAt());  // occurredAt 사용
    }
}