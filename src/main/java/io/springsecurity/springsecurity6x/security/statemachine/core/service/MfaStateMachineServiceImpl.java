package io.springsecurity.springsecurity6x.security.statemachine.core.service;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
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
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * MFA State Machine 서비스 구현체 - 단일 진실의 원천(Single Source of Truth)
 * FactorContext의 모든 상태를 State Machine에서 관리
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachinePool stateMachinePool;
    private final FactorContextStateAdapter factorContextAdapter;
    private final MfaEventPublisher eventPublisher;
    private final RedisDistributedLockService distributedLockService;
    private final OptimisticLockManager optimisticLockManager;

    // ContextPersistence 완전 제거 - State Machine이 유일한 저장소
    private final ConcurrentHashMap<String, ExecutorService> sessionExecutors = new ConcurrentHashMap<>();
    private final AtomicReference<CircuitState> circuitState = new AtomicReference<>(CircuitState.CLOSED);
    private volatile long lastFailureTime = 0;
    private final AtomicReference<Integer> failureCount = new AtomicReference<>(0);

    @Value("${security.statemachine.circuit-breaker.failure-threshold:5}")
    private int failureThreshold;

    @Value("${security.statemachine.circuit-breaker.timeout-seconds:30}")
    private int circuitBreakerTimeout;

    @Value("${security.statemachine.operation-timeout-seconds:10}")
    private int operationTimeout;

    // 세션별 전용 실행자 관리
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

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing state machine for session: {} as single source of truth", sessionId);

        if (!isCircuitClosed()) {
            throw new StateMachineException("Circuit breaker is open");
        }

        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                distributedLockService.executeWithLock("sm:init:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {

                    PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).join();

                    try {
                        StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                        // FactorContext를 State Machine에 완전히 저장 (유일한 저장소)
                        storeFactorContextInStateMachine(stateMachine, context);

                        // 상태 머신 시작
                        if (!stateMachine.isComplete() && stateMachine.getState() == null) {
                            stateMachine.startReactively().block(Duration.ofSeconds(5));
                        }

                        // 초기 이벤트 전송
                        Message<MfaEvent> message = MessageBuilder
                                .withPayload(MfaEvent.PRIMARY_AUTH_SUCCESS)
                                .setHeader("sessionId", sessionId)
                                .setHeader("timestamp", System.currentTimeMillis())
                                .setHeader("request", request)
                                .build();

                        boolean accepted = stateMachine.sendEvent(message);

                        if (accepted) {
                            eventPublisher.publishStateChange(
                                    sessionId,
                                    MfaState.NONE,
                                    stateMachine.getState().getId(),
                                    MfaEvent.PRIMARY_AUTH_SUCCESS
                            );
                            onSuccess();
                            log.info("State machine initialized successfully for session: {}", sessionId);
                        } else {
                            throw new StateMachineException("Failed to process PRIMARY_AUTH_SUCCESS event");
                        }
                    } finally {
                        // State Machine 반환 시 자동으로 Redis에 저장됨
                        stateMachinePool.returnStateMachine(sessionId).join();
                    }

                    return null;
                });
            } catch (Exception e) {
                onFailure();
                log.error("Failed to initialize state machine for session: {}", sessionId, e);
                throw new StateMachineException("Failed to initialize state machine", e);
            }
        }, executor);

        try {
            future.get(operationTimeout, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new StateMachineException("State machine initialization timeout", e);
        } catch (Exception e) {
            throw new StateMachineException("State machine initialization failed", e);
        }
    }

    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Sending event {} for session: {} via single source of truth", event, sessionId);

        if (!isCircuitClosed()) {
            log.error("Circuit breaker is open, rejecting event");
            return false;
        }

        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
            long startTime = System.currentTimeMillis();

            try {
                return distributedLockService.executeWithLock("sm:event:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {

                    PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).join();

                    try {
                        StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                        // State Machine의 현재 상태가 진실의 원천
                        MfaState currentState = stateMachine.getState().getId();

                        // State Machine에서 최신 FactorContext 재구성
                        FactorContext latestContext = reconstructFactorContextFromStateMachine(stateMachine);

                        // 클라이언트 컨텍스트의 변경사항 병합 (속성 및 비즈니스 데이터만)
                        mergeContextChanges(latestContext, context);

                        // 병합된 최신 데이터를 State Machine에 다시 저장
                        storeFactorContextInStateMachine(stateMachine, latestContext);

                        // 이벤트 메시지 생성
                        Message<MfaEvent> message = createEventMessage(event, latestContext, request);
                        boolean accepted = stateMachine.sendEvent(message);

                        if (accepted) {
                            MfaState newState = stateMachine.getState().getId();

                            // 상태 전환 완료 후 FactorContext 업데이트
                            updateFactorContextFromStateMachine(latestContext, stateMachine);

                            // 클라이언트 컨텍스트에 최신 상태 반영
                            syncFactorContextStates(context, latestContext);

                            Duration duration = Duration.ofMillis(System.currentTimeMillis() - startTime);
                            eventPublisher.publishStateChange(sessionId, currentState, newState, event, duration);

                            log.info("Event {} accepted, state transition: {} -> {} for session: {}",
                                    event, currentState, newState, sessionId);
                            onSuccess();
                        } else {
                            log.warn("Event {} rejected in state {} for session: {}",
                                    event, currentState, sessionId);
                        }

                        return accepted;

                    } finally {
                        // State Machine 반환 시 자동으로 Redis에 저장됨
                        stateMachinePool.returnStateMachine(sessionId);
                    }
                });
            } catch (Exception e) {
                onFailure();
                eventPublisher.publishError(sessionId, context.getCurrentState(), event, e);
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

    @Override
    public MfaState getCurrentState(String sessionId) {
        try {
            // 캐시 우선 확인
            MfaState cachedState = optimisticLockManager.getCachedState(sessionId);
            if (cachedState != null) {
                return cachedState;
            }

            return distributedLockService.executeWithLock("sm:state:" + sessionId, Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 5, TimeUnit.SECONDS
                ).join();

                try {
                    MfaState state = pooled.getStateMachine().getState().getId();
                    optimisticLockManager.updateCachedState(sessionId, state);
                    return state;
                } finally {
                    stateMachinePool.returnStateMachine(sessionId);
                }
            });
        } catch (Exception e) {
            log.error("Failed to get current state for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    /**
     * FactorContext 조회 - State Machine에서만 조회 (단일 진실의 원천)
     */
    public FactorContext getFactorContext(String sessionId) {
        try {
            return distributedLockService.executeWithLock("sm:context:" + sessionId, Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 5, TimeUnit.SECONDS
                ).join();

                try {
                    return reconstructFactorContextFromStateMachine(pooled.getStateMachine());
                } finally {
                    stateMachinePool.returnStateMachine(sessionId);
                }
            });
        } catch (Exception e) {
            log.error("Failed to get FactorContext for session: {}", sessionId, e);
            return null;
        }
    }

    /**
     * FactorContext 저장 - State Machine에만 저장
     */
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        try {
            distributedLockService.executeWithLock("sm:save:" + sessionId, Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 5, TimeUnit.SECONDS
                ).join();

                try {
                    storeFactorContextInStateMachine(pooled.getStateMachine(), context);
                    log.debug("FactorContext saved to State Machine for session: {}", sessionId);
                } finally {
                    stateMachinePool.returnStateMachine(sessionId);
                }

                return null;
            });
        } catch (Exception e) {
            log.error("Failed to save FactorContext for session: {}", sessionId, e);
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing state machine for session: {}", sessionId);

        // 세션별 실행자 정리
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

        // 비동기 정리 작업
        CompletableFuture.runAsync(() -> {
            try {
                optimisticLockManager.clearCache(sessionId);
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
     * State Machine에 FactorContext 저장
     */
    private void storeFactorContextInStateMachine(StateMachine<MfaState, MfaEvent> stateMachine,
                                                  FactorContext context) {
        Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);

        // 메타데이터 추가
        variables.put("_lastUpdated", Instant.now().toEpochMilli());
        variables.put("_version", context.getVersion());
        variables.put("_stateHash", context.calculateStateHash());

        // 완전 교체
        stateMachine.getExtendedState().getVariables().clear();
        stateMachine.getExtendedState().getVariables().putAll(variables);

        log.debug("FactorContext stored in State Machine: sessionId={}, version={}, state={}",
                context.getMfaSessionId(), context.getVersion(), context.getCurrentState());
    }

    /**
     * State Machine에서 FactorContext 재구성
     */
    private FactorContext reconstructFactorContextFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        return factorContextAdapter.reconstructFromStateMachine(stateMachine);
    }

    /**
     * State Machine에서 FactorContext 업데이트
     */
    private void updateFactorContextFromStateMachine(FactorContext context,
                                                     StateMachine<MfaState, MfaEvent> stateMachine) {
        factorContextAdapter.updateFactorContext(stateMachine, context);
    }

    /**
     * 컨텍스트 변경사항 병합 (상태는 제외하고 속성만)
     */
    private void mergeContextChanges(FactorContext target, FactorContext source) {
        // 상태는 State Machine이 관리하므로 병합하지 않음
        // 비즈니스 속성만 병합
        source.getAttributes().forEach((key, value) -> {
            if (!"currentState".equals(key) && !"version".equals(key) && !"lastUpdated".equals(key)) {
                target.setAttribute(key, value);
            }
        });

        // 시도 횟수 및 실패 정보 병합
        target.setRetryCount(Math.max(target.getRetryCount(), source.getRetryCount()));
        if (source.getLastError() != null) {
            target.setLastError(source.getLastError());
        }
    }

    /**
     * FactorContext 상태 동기화 (State Machine -> FactorContext)
     */
    private void syncFactorContextStates(FactorContext target, FactorContext source) {
        target.changeState(source.getCurrentState());
        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setCurrentFactorOptions(source.getCurrentFactorOptions());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());
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
                .setHeader("stateHash", context.calculateStateHash())
                .build();
    }

    /**
     * Circuit Breaker 상태 관리
     */
    private boolean isCircuitClosed() {
        CircuitState state = circuitState.get();

        if (state == CircuitState.OPEN) {
            if (System.currentTimeMillis() - lastFailureTime > circuitBreakerTimeout * 1000) {
                circuitState.compareAndSet(CircuitState.OPEN, CircuitState.HALF_OPEN);
                log.info("Circuit breaker transitioned to HALF_OPEN");
                return true;
            }
            return false;
        }

        return true;
    }

    private void onSuccess() {
        if (circuitState.get() == CircuitState.HALF_OPEN) {
            circuitState.set(CircuitState.CLOSED);
            failureCount.set(0);
            log.info("Circuit breaker closed after successful operation");
        }
    }

    private void onFailure() {
        lastFailureTime = System.currentTimeMillis();
        int count = failureCount.updateAndGet(c -> c + 1);

        if (count >= failureThreshold) {
            circuitState.set(CircuitState.OPEN);
            log.error("Circuit breaker opened after {} failures", count);
        }
    }

    public void shutdown() {
        log.info("Shutting down MFA State Machine Service");

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

    private enum CircuitState {
        CLOSED,
        OPEN,
        HALF_OPEN
    }

    public static class StateMachineException extends RuntimeException {
        public StateMachineException(String message) {
            super(message);
        }

        public StateMachineException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}