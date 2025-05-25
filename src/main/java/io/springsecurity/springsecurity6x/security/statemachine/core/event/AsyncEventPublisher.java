package io.springsecurity.springsecurity6x.security.statemachine.core.event;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 비동기 이벤트 발행자
 * - 논블로킹 이벤트 처리
 * - 배치 처리 및 백프레셔 제어
 * - 실패 시 재시도 메커니즘
 */
@Slf4j
public class AsyncEventPublisher implements MfaEventPublisher {

    private final ApplicationEventPublisher applicationEventPublisher;
    private final RedisTemplate<String, String> redisTemplate;

    // 이벤트 큐 및 배치 처리
    private final BlockingQueue<EventMessage> eventQueue = new LinkedBlockingQueue<>(10000);
    private final ScheduledExecutorService batchProcessor = Executors.newScheduledThreadPool(2);

    // 통계 정보
    private final AtomicLong totalPublished = new AtomicLong(0);
    private final AtomicLong totalFailed = new AtomicLong(0);
    private final AtomicLong totalRetried = new AtomicLong(0);

    // 백프레셔 제어
    private final Semaphore backpressureSemaphore = new Semaphore(1000);

    public AsyncEventPublisher(ApplicationEventPublisher applicationEventPublisher, RedisTemplate<String, String> redisTemplate) {
        this.applicationEventPublisher = applicationEventPublisher;
        this.redisTemplate = redisTemplate;
        // 배치 처리 시작
        startBatchProcessor();
    }

    @Override
    public void publishStateChange(String sessionId, MfaState state, MfaEvent event) {
        publishStateChangeAsync(sessionId, null, state, event);
    }

    @Override
    public void publishError(String sessionId, Exception error) {
        publishErrorAsync(sessionId, error);
    }

    @Override
    public void publishCustomEvent(String eventType, Object payload) {
        publishCustomEventAsync(eventType, payload);
    }

    /**
     * 비동기 상태 변경 이벤트 발행
     */
    public CompletableFuture<Void> publishStateChangeAsync(String sessionId, MfaState fromState,
                                                           MfaState toState, MfaEvent event) {
        return CompletableFuture.runAsync(() -> {
            try {
                // 백프레셔 제어
                if (!backpressureSemaphore.tryAcquire(5, TimeUnit.SECONDS)) {
                    log.warn("Event publishing backpressure for session: {}", sessionId);
                    return;
                }

                try {
                    EventMessage message = EventMessage.builder()
                            .type(EventType.STATE_CHANGE)
                            .sessionId(sessionId)
                            .fromState(fromState)
                            .toState(toState)
                            .event(event)
                            .timestamp(System.currentTimeMillis())
                            .build();

                    if (!eventQueue.offer(message, 1, TimeUnit.SECONDS)) {
                        log.error("Event queue full, dropping event for session: {}", sessionId);
                        totalFailed.incrementAndGet();
                    }
                } finally {
                    backpressureSemaphore.release();
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Interrupted while publishing state change event", e);
            }
        });
    }

    /**
     * 비동기 에러 이벤트 발행
     */
    public CompletableFuture<Void> publishErrorAsync(String sessionId, Exception error) {
        return CompletableFuture.runAsync(() -> {
            EventMessage message = EventMessage.builder()
                    .type(EventType.ERROR)
                    .sessionId(sessionId)
                    .error(error)
                    .timestamp(System.currentTimeMillis())
                    .build();

            try {
                eventQueue.offer(message, 100, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Failed to queue error event", e);
            }
        });
    }

    /**
     * 비동기 커스텀 이벤트 발행
     */
    public CompletableFuture<Void> publishCustomEventAsync(String eventType, Object payload) {
        return CompletableFuture.runAsync(() -> {
            EventMessage message = EventMessage.builder()
                    .type(EventType.CUSTOM)
                    .customType(eventType)
                    .payload(payload)
                    .timestamp(System.currentTimeMillis())
                    .build();

            try {
                eventQueue.offer(message, 100, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Failed to queue custom event", e);
            }
        });
    }

    /**
     * 배치 처리 시작
     */
    private void startBatchProcessor() {
        // 배치 이벤트 처리
        batchProcessor.scheduleWithFixedDelay(() -> {
            try {
                processBatch();
            } catch (Exception e) {
                log.error("Error in batch processor", e);
            }
        }, 100, 100, TimeUnit.MILLISECONDS);

        // 통계 로깅
        batchProcessor.scheduleWithFixedDelay(() -> {
            log.info("Event Publisher Stats - Published: {}, Failed: {}, Retried: {}, Queue Size: {}",
                    totalPublished.get(), totalFailed.get(), totalRetried.get(), eventQueue.size());
        }, 1, 1, TimeUnit.MINUTES);
    }

    /**
     * 배치 처리
     */
    private void processBatch() {
        int batchSize = Math.min(eventQueue.size(), 100);
        if (batchSize == 0) {
            return;
        }

        Map<EventType, CompletableFuture<Void>> futures = new HashMap<>();

        for (int i = 0; i < batchSize; i++) {
            EventMessage message = eventQueue.poll();
            if (message == null) break;

            // 타입별로 그룹화하여 처리
            futures.computeIfAbsent(message.type, k -> CompletableFuture.runAsync(() -> {
                processEventType(message.type, message);
            }));
        }

        // 모든 Future 완료 대기
        CompletableFuture.allOf(futures.values().toArray(new CompletableFuture[0]))
                .orTimeout(5, TimeUnit.SECONDS)
                .exceptionally(ex -> {
                    log.error("Batch processing timeout", ex);
                    return null;
                });
    }

    /**
     * 이벤트 타입별 처리
     */
    private void processEventType(EventType type, EventMessage message) {
        try {
            switch (type) {
                case STATE_CHANGE:
                    processStateChangeEvent(message);
                    break;
                case ERROR:
                    processErrorEvent(message);
                    break;
                case CUSTOM:
                    processCustomEvent(message);
                    break;
            }

            totalPublished.incrementAndGet();

        } catch (Exception e) {
            log.error("Failed to process event: {}", message, e);
            handleFailedEvent(message, e);
        }
    }

    /**
     * 상태 변경 이벤트 처리
     */
    private void processStateChangeEvent(EventMessage message) {
        // 로컬 이벤트 발행
        MfaStateChangeEvent event = new MfaStateChangeEvent(
                this,
                message.sessionId,
                message.toState,
                message.event,
                LocalDateTime.now()
        );
        applicationEventPublisher.publishEvent(event);

        // Redis 발행
        if (redisTemplate != null) {
            try {
                Map<String, Object> redisMessage = new HashMap<>();
                redisMessage.put("type", "STATE_CHANGE");
                redisMessage.put("sessionId", message.sessionId);
                redisMessage.put("fromState", message.fromState != null ? message.fromState.name() : null);
                redisMessage.put("toState", message.toState.name());
                redisMessage.put("event", message.event.name());
                redisMessage.put("timestamp", message.timestamp);

                redisTemplate.convertAndSend("mfa:events:state-change", redisMessage);
            } catch (Exception e) {
                log.warn("Failed to publish to Redis", e);
            }
        }
    }

    /**
     * 에러 이벤트 처리
     */
    private void processErrorEvent(EventMessage message) {
        MfaErrorEvent event = new MfaErrorEvent(
                this,
                message.sessionId,
                message.error,
                LocalDateTime.now()
        );
        applicationEventPublisher.publishEvent(event);
    }

    /**
     * 커스텀 이벤트 처리
     */
    private void processCustomEvent(EventMessage message) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("eventType", message.customType);
        eventData.put("payload", message.payload);
        eventData.put("timestamp", LocalDateTime.now());

        applicationEventPublisher.publishEvent(eventData);
    }

    /**
     * 실패한 이벤트 처리
     */
    private void handleFailedEvent(EventMessage message, Exception error) {
        totalFailed.incrementAndGet();

        // 재시도 횟수 확인
        if (message.retryCount < 3) {
            message.retryCount++;
            totalRetried.incrementAndGet();

            // 지수 백오프로 재시도
            batchProcessor.schedule(() -> {
                try {
                    eventQueue.offer(message);
                } catch (Exception e) {
                    log.error("Failed to requeue event", e);
                }
            }, (long) Math.pow(2, message.retryCount), TimeUnit.SECONDS);
        } else {
            log.error("Event permanently failed after {} retries: {}", message.retryCount, message);
        }
    }

    /**
     * 종료 처리
     */
    public void shutdown() {
        log.info("Shutting down AsyncEventPublisher");

        batchProcessor.shutdown();
        try {
            // 남은 이벤트 처리
            processBatch();

            if (!batchProcessor.awaitTermination(10, TimeUnit.SECONDS)) {
                batchProcessor.shutdownNow();
            }
        } catch (InterruptedException e) {
            batchProcessor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        log.info("AsyncEventPublisher shutdown complete. Final stats - Published: {}, Failed: {}",
                totalPublished.get(), totalFailed.get());
    }

    /**
     * 이벤트 메시지
     */
    @Builder
    @Getter
    private static class EventMessage {
        private final EventType type;
        private final String sessionId;
        private final MfaState fromState;
        private final MfaState toState;
        private final MfaEvent event;
        private final Exception error;
        private final String customType;
        private final Object payload;
        private final long timestamp;
        private int retryCount;
    }

    /**
     * 이벤트 타입
     */
    private enum EventType {
        STATE_CHANGE,
        ERROR,
        CUSTOM
    }

    /**
     * MFA 상태 변경 이벤트
     */
    public static class MfaStateChangeEvent {
        private final Object source;
        private final String sessionId;
        private final MfaState state;
        private final MfaEvent event;
        private final LocalDateTime timestamp;

        public MfaStateChangeEvent(Object source, String sessionId,
                                   MfaState state, MfaEvent event,
                                   LocalDateTime timestamp) {
            this.source = source;
            this.sessionId = sessionId;
            this.state = state;
            this.event = event;
            this.timestamp = timestamp;
        }

        // Getters
        public Object getSource() { return source; }
        public String getSessionId() { return sessionId; }
        public MfaState getState() { return state; }
        public MfaEvent getEvent() { return event; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    /**
     * MFA 에러 이벤트
     */
    public static class MfaErrorEvent {
        private final Object source;
        private final String sessionId;
        private final Exception error;
        private final LocalDateTime timestamp;

        public MfaErrorEvent(Object source, String sessionId,
                             Exception error, LocalDateTime timestamp) {
            this.source = source;
            this.sessionId = sessionId;
            this.error = error;
            this.timestamp = timestamp;
        }

        // Getters
        public Object getSource() { return source; }
        public String getSessionId() { return sessionId; }
        public Exception getError() { return error; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}