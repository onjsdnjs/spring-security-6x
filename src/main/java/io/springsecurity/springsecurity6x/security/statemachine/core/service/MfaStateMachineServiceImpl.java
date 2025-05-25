package io.springsecurity.springsecurity6x.security.statemachine.core.service;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.core.event.MfaEventPublisher;
import io.springsecurity.springsecurity6x.security.statemachine.core.lock.OptimisticLockManager;
import io.springsecurity.springsecurity6x.security.statemachine.core.pool.PooledStateMachine;
import io.springsecurity.springsecurity6x.security.statemachine.core.pool.StateMachinePool;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachine;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachinePool stateMachinePool;
    private final FactorContextStateAdapter factorContextAdapter;
    private final ContextPersistence contextPersistence;
    private final MfaEventPublisher eventPublisher;
    private final RedisDistributedLockService distributedLockService;
    private final OptimisticLockManager optimisticLockManager;

    // 세션별 순차 처리를 위한 Executor 관리
    private final ConcurrentHashMap<String, ExecutorService> sessionExecutors = new ConcurrentHashMap<>();

    // 세션별 처리 큐
    private final ConcurrentHashMap<String, BlockingQueue<Runnable>> sessionQueues = new ConcurrentHashMap<>();

    // Circuit Breaker 상태
    private final AtomicReference<CircuitState> circuitState = new AtomicReference<>(CircuitState.CLOSED);
    private volatile long lastFailureTime = 0;
    private final AtomicReference<Integer> failureCount = new AtomicReference<>(0);

    @Value("${security.statemachine.circuit-breaker.failure-threshold:5}")
    private int failureThreshold;

    @Value("${security.statemachine.circuit-breaker.timeout-seconds:30}")
    private int circuitBreakerTimeout;

    @Value("${security.statemachine.operation-timeout-seconds:10}")
    private int operationTimeout;

    /**
     * 세션별 순차 처리를 보장하는 Executor 가져오기
     */
    private ExecutorService getSessionExecutor(String sessionId) {
        return sessionExecutors.computeIfAbsent(sessionId, k -> {
            ThreadFactory threadFactory = r -> {
                Thread thread = new Thread(r, "MFA-Session-" + sessionId);
                thread.setDaemon(true);
                return thread;
            };
            return Executors.newSingleThreadExecutor(threadFactory);
        });
    }

    /**
     * State Machine 초기화 - 순차 처리 보장
     */
    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing state machine for session: {}", sessionId);

        // Circuit Breaker 확인
        if (!isCircuitClosed()) {
            throw new StateMachineException("Circuit breaker is open");
        }

        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                // Distributed Lock 획득
                distributedLockService.executeWithLock("sm:init:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {

                    // State Machine Pool에서 대여
                    PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).join();

                    try {
                        StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                        // State Machine을 Primary Source로 설정
                        synchronizeStateFromStateMachine(stateMachine, context);

                        // 초기 컨텍스트 설정
                        Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
                        stateMachine.getExtendedState().getVariables().putAll(variables);

                        // State Machine 시작
                        if (!stateMachine.isComplete() && stateMachine.getState() == null) {
                            stateMachine.start();
                        }

                        // PRIMARY_AUTH_SUCCESS 이벤트 전송
                        Message<MfaEvent> message = MessageBuilder
                                .withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS)
                                .setHeader("sessionId", sessionId)
                                .setHeader("timestamp", System.currentTimeMillis())
                                .build();

                        boolean accepted = stateMachine.sendEvent(message);

                        if (accepted) {
                            // State Machine의 상태로 Context 업데이트
                            synchronizeStateFromStateMachine(stateMachine, context);

                            // Context 업데이트 및 저장
                            factorContextAdapter.updateFactorContext(stateMachine, context);
                            contextPersistence.saveContext(context, request);

                            // 이벤트 발행
                            eventPublisher.publishStateChange(
                                    sessionId,
                                    MfaState.NONE,
                                    stateMachine.getState().getId(),
                                    MfaEvent.PRIMARY_AUTH_SUCCESS
                            );

                            // 성공 시 Circuit Breaker 리셋
                            onSuccess();
                        } else {
                            throw new StateMachineException("Failed to process PRIMARY_AUTH_SUCCESS event");
                        }
                    } finally {
                        // State Machine 반환
                        stateMachinePool.returnStateMachine(sessionId).join();
                    }

                    return null;
                });
            } catch (Exception e) {
                onFailure();
                throw new StateMachineException("Failed to initialize state machine", e);
            }
        }, executor);

        // 타임아웃 적용
        try {
            future.get(operationTimeout, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new StateMachineException("State machine initialization timeout", e);
        } catch (Exception e) {
            throw new StateMachineException("State machine initialization failed", e);
        }
    }

    /**
     * 이벤트 전송 - 순차 처리 보장
     */
    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Sending event {} for session: {}", event, sessionId);

        // Circuit Breaker 확인
        if (!isCircuitClosed()) {
            log.error("Circuit breaker is open, rejecting event");
            return false;
        }

        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
            long startTime = System.currentTimeMillis();

            try {
                return distributedLockService.executeWithLock("sm:event:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {

                    // State Machine Pool에서 대여
                    PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).join();

                    try {
                        StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                        // State Machine의 현재 상태로 Context 동기화
                        synchronizeStateFromStateMachine(stateMachine, context);

                        // 현재 상태 저장
                        MfaState currentState = stateMachine.getState().getId();

                        // Context 동기화
                        Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
                        stateMachine.getExtendedState().getVariables().putAll(variables);

                        // 이벤트 메시지 생성
                        Message<MfaEvent> message = createEventMessage(event, context, request);

                        // 이벤트 전송
                        boolean accepted = stateMachine.sendEvent(message);

                        if (accepted) {
                            MfaState newState = stateMachine.getState().getId();

                            // State Machine의 상태로 Context 업데이트
                            synchronizeStateFromStateMachine(stateMachine, context);

                            // Context 업데이트
                            factorContextAdapter.updateFactorContext(stateMachine, context);

                            // 버전 증가
                            context.incrementVersion();
                            optimisticLockManager.updateVersion(sessionId, context.getVersion().get());

                            // Context 저장
                            contextPersistence.saveContext(context, request);

                            // 전이 시간 계산
                            Duration duration = Duration.ofMillis(System.currentTimeMillis() - startTime);

                            // 이벤트 발행
                            eventPublisher.publishStateChange(sessionId, currentState, newState, event, duration);

                            log.info("Event {} accepted, state transition: {} -> {} for session: {}",
                                    event, currentState, newState, sessionId);
                        } else {
                            log.warn("Event {} rejected in state {} for session: {}",
                                    event, currentState, sessionId);
                        }

                        onSuccess();
                        return accepted;

                    } finally {
                        // State Machine 반환
                        stateMachinePool.returnStateMachine(sessionId);
                    }
                });
            } catch (Exception e) {
                onFailure();

                // 에러 이벤트 발행
                eventPublisher.publishError(
                        sessionId,
                        context.getCurrentState(),
                        event,
                        e
                );

                log.error("Failed to send event {} for session: {}", event, sessionId, e);
                return false;
            }
        }, executor);

        try {
            return future.get(operationTimeout, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            log.error("Event processing timeout for session: {}", sessionId);
            return false;
        } catch (Exception e) {
            log.error("Event processing failed for session: {}", sessionId, e);
            return false;
        }
    }

    /**
     * State Machine의 상태를 FactorContext에 동기화
     */
    private void synchronizeStateFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine,
                                                  FactorContext context) {
        if (stateMachine.getState() != null) {
            MfaState currentState = stateMachine.getState().getId();
            if (context.getCurrentState() != currentState) {
                log.debug("Synchronizing state from State Machine: {} -> {}",
                        context.getCurrentState(), currentState);
                context.changeState(currentState);
            }
        }
    }

    /**
     * 현재 상태 조회 - State Machine이 Primary Source
     */
    @Override
    public MfaState getCurrentState(String sessionId) {
        try {
            // 먼저 캐시된 상태 확인
            MfaState cachedState = optimisticLockManager.getCachedState(sessionId);
            if (cachedState != null) {
                return cachedState;
            }

            // Pool에서 State Machine 가져와서 확인
            return distributedLockService.executeWithLock("sm:state:" + sessionId, Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 5, TimeUnit.SECONDS
                ).join();

                try {
                    MfaState state = pooled.getStateMachine().getState().getId();

                    // 캐시 업데이트
                    optimisticLockManager.updateCachedState(sessionId, state);

                    return state;
                } finally {
                    stateMachinePool.returnStateMachine(sessionId);
                }
            });
        } catch (Exception e) {
            log.error("Failed to get current state for session: {}", sessionId, e);

            // Fallback: Context에서 상태 가져오기
            try {
                FactorContext context = contextPersistence.loadContext(sessionId, null);
                return context != null ? context.getCurrentState() : MfaState.NONE;
            } catch (Exception ex) {
                return MfaState.NONE;
            }
        }
    }

    /**
     * State Machine 해제
     */
    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing state machine for session: {}", sessionId);

        // 세션별 Executor 정리
        ExecutorService executor = sessionExecutors.remove(sessionId);
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        CompletableFuture.runAsync(() -> {
            try {
                // 캐시 정리
                optimisticLockManager.clearCache(sessionId);

                // Context 정리
                contextPersistence.deleteContext(null);

                // 완료 이벤트 발행
                eventPublisher.publishCustomEvent("SESSION_CLEANUP", Map.of(
                        "sessionId", sessionId,
                        "timestamp", System.currentTimeMillis()
                ));

            } catch (Exception e) {
                log.error("Error releasing state machine for session: {}", sessionId, e);
            }
        });
    }

    /**
     * 이벤트 메시지 생성
     */
    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context, HttpServletRequest request) {
        return MessageBuilder
                .withPayload(event)
                .setHeader("sessionId", context.getMfaSessionId())
                .setHeader("username", context.getUsername())
                .setHeader("timestamp", System.currentTimeMillis())
                .setHeader("authentication", context.getPrimaryAuthentication())
                .setHeader("request", request)
                .setHeader("version", context.getVersion())
                .build();
    }

    /**
     * Circuit Breaker 상태 확인
     */
    private boolean isCircuitClosed() {
        CircuitState state = circuitState.get();

        if (state == CircuitState.OPEN) {
            // 타임아웃 확인
            if (System.currentTimeMillis() - lastFailureTime > circuitBreakerTimeout * 1000) {
                circuitState.compareAndSet(CircuitState.OPEN, CircuitState.HALF_OPEN);
                log.info("Circuit breaker transitioned to HALF_OPEN");
                return true;
            }
            return false;
        }

        return true;
    }

    /**
     * 성공 처리
     */
    private void onSuccess() {
        if (circuitState.get() == CircuitState.HALF_OPEN) {
            circuitState.set(CircuitState.CLOSED);
            failureCount.set(0);
            log.info("Circuit breaker closed after successful operation");
        }
    }

    /**
     * 실패 처리
     */
    private void onFailure() {
        lastFailureTime = System.currentTimeMillis();
        int count = failureCount.updateAndGet(c -> c + 1);

        if (count >= failureThreshold) {
            circuitState.set(CircuitState.OPEN);
            log.error("Circuit breaker opened after {} failures", count);
        }
    }

    /**
     * 서비스 종료
     */
    public void shutdown() {
        log.info("Shutting down MFA State Machine Service");

        // 모든 세션 Executor 종료
        sessionExecutors.forEach((sessionId, executor) -> {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }
        });
        sessionExecutors.clear();

        stateMachinePool.shutdown();
    }

    /**
     * Circuit Breaker 상태
     */
    private enum CircuitState {
        CLOSED,     // 정상 작동
        OPEN,       // 차단 상태
        HALF_OPEN   // 테스트 상태
    }

    /**
     * State Machine 예외
     */
    public static class StateMachineException extends RuntimeException {
        public StateMachineException(String message) {
            super(message);
        }

        public StateMachineException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}