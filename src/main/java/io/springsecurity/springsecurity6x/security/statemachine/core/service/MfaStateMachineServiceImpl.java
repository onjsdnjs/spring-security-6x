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
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

@Slf4j
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachinePool stateMachinePool;
    private final FactorContextStateAdapter factorContextAdapter;
    private final MfaEventPublisher eventPublisher;
    private final RedisDistributedLockService distributedLockService;
    private final OptimisticLockManager optimisticLockManager;

    private final ConcurrentHashMap<String, ExecutorService> sessionExecutors = new ConcurrentHashMap<>();
    private final AtomicReference<CircuitState> circuitState = new AtomicReference<>(CircuitState.CLOSED);
    private volatile long lastFailureTime = 0;
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicInteger activeOperations = new AtomicInteger(0);
    private final ConcurrentHashMap<String, Long> operationTimings = new ConcurrentHashMap<>();

    @Value("${security.statemachine.circuit-breaker.failure-threshold:5}")
    private int failureThreshold;
    @Value("${security.statemachine.circuit-breaker.timeout-seconds:30}")
    private int circuitBreakerTimeout;
    @Value("${security.statemachine.operation-timeout-seconds:10}")
    private int operationTimeout;
    @Value("${security.statemachine.max-retry-attempts:3}")
    private int maxRetryAttempts;

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        long startTime = System.currentTimeMillis();

        log.info("Initializing State Machine for session: {}", sessionId);

        if (!isCircuitClosed()) {
            log.error("Circuit breaker is open - system protection activated. Cannot initialize SM for session: {}", sessionId);
            throw new StateMachineException("Circuit breaker is open - system protection activated");
        }

        activeOperations.incrementAndGet();
        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                distributedLockService.executeWithLock("sm:init:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {
                    PooledStateMachine pooled = null;
                    try {
                        pooled = stateMachinePool.borrowStateMachine(
                                sessionId, operationTimeout, TimeUnit.SECONDS
                        ).get(operationTimeout, TimeUnit.SECONDS);

                        StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();
                        validateStateMachine(stateMachine, sessionId); // 상태 머신 유효성 검사 및 시작 보장

                        // State Machine이 시작된 후에 FactorContext 저장
                        storeFactorContextInStateMachine(stateMachine, context);

                        Message<MfaEvent> message = createEventMessage(
                                MfaEvent.PRIMARY_AUTH_SUCCESS, context, request);

                        boolean accepted = stateMachine.sendEvent(message);

                        if (accepted) {
                            MfaState newState = stateMachine.getState().getId();
                            // 상태 머신 변경 후 FactorContext 업데이트
                            factorContextAdapter.updateFactorContext(stateMachine, context);
                            publishStateChangeAsync(sessionId, MfaState.NONE, newState, MfaEvent.PRIMARY_AUTH_SUCCESS, Duration.ofMillis(System.currentTimeMillis() - startTime));
                            onSuccess(); // 회로 차단기 성공 처리
                            log.info("State Machine initialized successfully for session: {} to state: {}", sessionId, newState);
                        } else {
                            // 이벤트 거부 시 상세 로깅 추가
                            log.error("State Machine rejected PRIMARY_AUTH_SUCCESS event for session: {}. Current SM state: {}, ExtendedState: {}",
                                    sessionId, stateMachine.getState() != null ? stateMachine.getState().getId() : "null", stateMachine.getExtendedState().getVariables());
                            throw new StateMachineException("Failed to process PRIMARY_AUTH_SUCCESS event during initialization");
                        }
                    } finally {
                        if (pooled != null) {
                            CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId))
                                    .exceptionally(ex -> {
                                        log.error("Error returning state machine to pool asynchronously for session: {}", sessionId, ex);
                                        return null;
                                    });
                        }
                    }
                    return null; // executeWithLock의 Supplier<T> 반환 타입
                });
            } catch (Exception e) {
                onFailure(); // 회로 차단기 실패 처리
                log.error("Failed to initialize State Machine for session: {}", sessionId, e);
                publishErrorAsync(sessionId, context.getCurrentState() != null ? context.getCurrentState() : MfaState.NONE, MfaEvent.PRIMARY_AUTH_SUCCESS, e);
                throw new StateMachineException("State Machine initialization failed: " + e.getMessage(), e);
            } finally {
                activeOperations.decrementAndGet();
                recordOperationTiming("initializeStateMachine", startTime);
            }
        }, executor);

        try {
            future.get(operationTimeout + 2, TimeUnit.SECONDS); // 타임아웃 버퍼 추가
        } catch (TimeoutException e) {
            future.cancel(true); // 작업 취소
            log.error("State Machine initialization timeout for session: {}", sessionId, e);
            throw new StateMachineException("State Machine initialization timeout", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            log.error("State Machine initialization failed execution for session: {}", sessionId, cause);
            if (cause instanceof StateMachineException) {
                throw (StateMachineException) cause;
            }
            throw new StateMachineException("State Machine initialization failed: " + (cause != null ? cause.getMessage() : "Unknown cause"), cause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            log.error("State Machine initialization interrupted for session: {}", sessionId, e);
            throw new StateMachineException("State Machine initialization interrupted", e);
        }
    }

    /**
     * 상태 머신 유효성 검사 및 시작 보장
     * @param stateMachine 상태 머신
     * @param sessionId 세션 ID
     */
    private void validateStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) {
        if (stateMachine == null) {
            throw new IllegalStateException("Borrowed null StateMachine for session: " + sessionId);
        }

        try {
            if (stateMachine.hasStateMachineError()) {
                log.error("StateMachine has error for session: {}. Attempting reset.", sessionId);
                stateMachine.stop(); // 비동기일 수 있음
                Thread.sleep(100); // 상태 전파 시간
                stateMachine.start(); // 비동기일 수 있음
                Thread.sleep(200); // 초기화 시간
                if (stateMachine.hasStateMachineError()) {
                    throw new IllegalStateException("StateMachine still in error state after reset for session: " + sessionId);
                }
            }

            if (stateMachine.getState() == null || stateMachine.getExtendedState().getVariables() == null) {
                log.info("StateMachine for session {} is not started or not fully initialized. Starting it now.", sessionId);
                stateMachine.start();
                Thread.sleep(300); // 초기화 대기 시간 증가
                if (stateMachine.getState() == null || stateMachine.getExtendedState().getVariables() == null) {
                    log.error("StateMachine for session {} failed to initialize extended state even after explicit start. Variables: {}", sessionId, stateMachine.getExtendedState().getVariables());
                    throw new IllegalStateException("StateMachine extended state not initialized after start for session: " + sessionId);
                }
            }
            log.debug("StateMachine for session {} validated. Current state: {}", sessionId, stateMachine.getState().getId());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StateMachineException("Interrupted during StateMachine validation for session: " + sessionId, e);
        } catch (Exception e) { // 보다 일반적인 예외 처리
            log.error("Unexpected error during StateMachine validation for session: {}", sessionId, e);
            throw new StateMachineException("StateMachine validation failed for session: " + sessionId, e);
        }
    }


    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        long startTime = System.currentTimeMillis();

        log.debug("Sending event {} for session: {} in FactorContext state: {}", event, sessionId, context.getCurrentState());

        if (!isCircuitClosed()) {
            log.error("Circuit breaker is open, rejecting event: {} for session: {}", event, sessionId);
            return false;
        }

        activeOperations.incrementAndGet();
        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
            try {
                return executeWithRetry(() -> processEventInternal(event, context, request),
                        maxRetryAttempts, sessionId, event.name());
            } catch (Exception e) {
                log.error("Exception during executeWithRetry for event {} session {}: {}", event, sessionId, e.getMessage(), e);
                onFailure();
                return false;
            }
        }, executor);

        try {
            boolean result = future.get(operationTimeout, TimeUnit.SECONDS);
            if (result) {
                onSuccess();
            } else {
                // processEventInternal이 false를 반환했거나, executeWithRetry에서 모든 재시도 후 실패
                // 이 경우 onFailure는 이미 executeWithRetry 또는 processEventInternal 내부에서 호출되었을 수 있음
                // 중복 호출을 피하기 위해, 여기서는 명시적으로 호출하지 않거나, 상태 기반으로 호출
                log.warn("sendEvent for session {} event {} resulted in false.", sessionId, event);
                // onFailure(); // executeWithRetry에서 이미 처리했을 수 있으므로, 조건부 호출 또는 제거 검토
            }
            return result;
        } catch (TimeoutException e) {
            future.cancel(true);
            log.error("Event processing timeout for session: {}, event: {}. Current SM state: {}. FactorContext state: {}", sessionId, event, getCurrentState(sessionId), context.getCurrentState(), e);
            onFailure();
            return false;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            log.error("Event processing failed execution for session: {}, event: {}. Current SM state: {}. FactorContext state: {}", sessionId, event, getCurrentState(sessionId), context.getCurrentState(), cause);
            onFailure();
            publishErrorAsync(sessionId, context.getCurrentState(), event, (Exception) cause);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            log.error("Event processing interrupted for session: {}, event: {}. Current SM state: {}. FactorContext state: {}", sessionId, event, getCurrentState(sessionId), context.getCurrentState(), e);
            onFailure();
            return false;
        } finally {
            activeOperations.decrementAndGet();
            recordOperationTiming("sendEvent:" + event.name(), startTime);
        }
    }

    private boolean processEventInternal(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        try {
            return distributedLockService.executeWithLock("sm:event:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {
                PooledStateMachine pooled = null;
                try {
                    pooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).get(operationTimeout, TimeUnit.SECONDS);

                    StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();
                    validateStateMachine(stateMachine, sessionId); // 상태 머신 유효성 검사 및 시작 보장

                    MfaState currentStateInSM = stateMachine.getState().getId();
                    log.debug("Processing event {} for session: {} from SM state: {}. FactorContext state: {}",
                            event, sessionId, currentStateInSM, context.getCurrentState());


                    // FactorContext를 상태 머신의 ExtendedState에 있는 정보와 동기화
                    FactorContext authoritativeContext = reconstructFactorContextFromStateMachine(stateMachine);
                    mergeBusinessDataOnly(authoritativeContext, context); // 외부 변경사항 병합
                    storeFactorContextInStateMachine(stateMachine, authoritativeContext); // SM에 최신 컨텍스트 저장


                    // 이벤트 전이 유효성 검증 (상태 머신의 실제 상태 기준)
                    if (!isValidEventTransition(currentStateInSM, event, stateMachine)) {
                        log.warn("Event {} rejected by pre-check for state machine state {} in session: {}. Variables: {}",
                                event, currentStateInSM, sessionId, stateMachine.getExtendedState().getVariables());
                        return false; // 이벤트 거부
                    }

                    Message<MfaEvent> message = createEventMessage(event, authoritativeContext, request);
                    boolean accepted = stateMachine.sendEvent(message);

                    if (accepted) {
                        MfaState newStateInSM = stateMachine.getState().getId();
                        // 상태 전이 후 FactorContext 업데이트 (SM이 진실의 원천)
                        factorContextAdapter.updateFactorContext(stateMachine, authoritativeContext);
                        // 변경된 authoritativeContext를 원래 context 객체에 다시 동기화
                        syncFactorContextFromStateMachine(context, authoritativeContext);

                        publishStateChangeAsync(sessionId, currentStateInSM, newStateInSM, event, null);
                        log.debug("Event {} processed by SM: {} -> {} for session: {}",
                                event, currentStateInSM, newStateInSM, sessionId);
                    } else {
                        log.warn("Event {} rejected by State Machine internal logic in state {} for session: {}. Variables: {}",
                                event, currentStateInSM, sessionId, stateMachine.getExtendedState().getVariables());
                    }
                    return accepted;
                } finally {
                    if (pooled != null) {
                        CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId))
                                .exceptionally(ex -> {
                                    log.error("Error returning state machine to pool asynchronously for session: {}", sessionId, ex);
                                    return null;
                                });
                    }
                }
            }); // End of executeWithLock lambda
        } catch (Exception e) {
            // executeWithRetry가 이 예외를 잡아서 재시도하거나 최종적으로 실패 처리.
            log.error("Failed to process event {} for session: {} within distributed lock.", event, sessionId, e);
            publishErrorAsync(sessionId, context.getCurrentState(), event, e);
            throw new StateMachineProcessingException("Event processing failed: " + e.getMessage(), e, context.getCurrentState(), event);
        }
    }


    @Override
    public FactorContext getFactorContext(String sessionId) {
        FactorContext cachedContext = optimisticLockManager.getCachedContext(sessionId);
        if (cachedContext != null && isContextValid(cachedContext)) {
            log.trace("Retrieved valid FactorContext from cache for session: {}", sessionId);
            return cachedContext;
        }

        if (cachedContext != null) { // Cache exists but invalid
            optimisticLockManager.invalidateContextCache(sessionId);
            log.debug("Invalidated stale cached context for session: {}", sessionId);
        }


        PooledStateMachine pooled = null;
        try {
            // 분산락은 짧게 잡도록 변경, SM 풀에서 가져오는 부분은 락 외부에서 수행
            pooled = stateMachinePool.borrowStateMachine(sessionId, operationTimeout, TimeUnit.SECONDS)
                    .get(operationTimeout, TimeUnit.SECONDS);
            StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();
            validateStateMachine(stateMachine, sessionId); // 상태 머신 유효성 검증 및 시작 보장

            FactorContext context = reconstructFactorContextFromStateMachine(stateMachine);

            if (context != null) {
                optimisticLockManager.updateCachedState(sessionId, context.getCurrentState());
                optimisticLockManager.updateCachedContext(sessionId, context);
                log.debug("FactorContext loaded and cached for session: {} in state {}", sessionId, context.getCurrentState());
            } else {
                log.warn("Reconstructed FactorContext is null for session: {}", sessionId);
            }
            return context;
        } catch (Exception e) {
            log.error("Failed to get FactorContext for session: {}", sessionId, e);
            return null;
        } finally {
            if (pooled != null) {
                final PooledStateMachine finalPooled = pooled; // Effectively final for lambda
                CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId))
                        .exceptionally(ex -> {
                            log.error("Error returning state machine to pool asynchronously for session: {}", sessionId, ex);
                            return null;
                        });
            }
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        PooledStateMachine pooled = null;
        try {
            distributedLockService.executeWithLock("sm:save:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {
                PooledStateMachine currentPooled = null; // Shadowing outer pooled
                try {
                    currentPooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).get(operationTimeout, TimeUnit.SECONDS);
                    StateMachine<MfaState, MfaEvent> stateMachine = currentPooled.getStateMachine();
                    validateStateMachine(stateMachine, sessionId); // 상태 머신 유효성 검증 및 시작 보장

                    storeFactorContextInStateMachine(stateMachine, context);

                    optimisticLockManager.updateCachedContext(sessionId, context);
                    optimisticLockManager.updateCachedState(sessionId, context.getCurrentState());

                    log.trace("FactorContext saved and cached for session: {} in state {}", sessionId, context.getCurrentState());
                } finally {
                    if (currentPooled != null) {
                        CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId))
                                .exceptionally(ex -> {
                                    log.error("Error returning state machine to pool asynchronously for session: {}", sessionId, ex);
                                    return null;
                                });
                    }
                }
                return null;
            });
        } catch (Exception e) {
            log.error("Failed to save FactorContext for session: {}", sessionId, e);
            throw new StateMachineException("Failed to save FactorContext: " + e.getMessage(), e);
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing State Machine for session: {}", sessionId);

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
                // 실제 StateMachinePool을 통해 반환 또는 정리 로직 호출
                stateMachinePool.returnStateMachine(sessionId).join(); // pool이 실제 SM을 관리하므로 pool에 반환
                optimisticLockManager.clearCache(sessionId);
                operationTimings.remove(sessionId);

                eventPublisher.publishCustomEvent("SESSION_CLEANUP_COMPLETED", Map.of(
                        "sessionId", sessionId,
                        "timestamp", System.currentTimeMillis(),
                        "activeOperations", activeOperations.get()
                ));
                log.info("State Machine and related resources released successfully for session: {}", sessionId);
            } catch (Exception e) {
                log.error("Error releasing State Machine and resources for session: {}", sessionId, e);
            }
        });
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        MfaState cachedState = optimisticLockManager.getCachedState(sessionId);
        if (cachedState != null) {
            // 캐시 유효성 검사 (예: TTL) 추가 가능
            if (isCachedStateValid(sessionId, cachedState)) {
                log.trace("Returning cached state {} for session: {}", cachedState, sessionId);
                return cachedState;
            } else {
                optimisticLockManager.invalidateCache(sessionId); // Stale cache
            }
        }

        PooledStateMachine pooled = null;
        try {
            // 분산락 없이 상태만 조회 시도, 실패 시 풀에서 가져와 조회
            // 이 부분은 캐시 미스 시에만 발생하므로, 락 없이 optimistic하게 시도 후 실패 시 풀 사용
            // 또는 항상 풀에서 가져와서 조회 (안정적이지만 약간의 오버헤드)
            // 여기서는 안정성을 위해 풀에서 가져오는 방식을 유지
            pooled = stateMachinePool.borrowStateMachine(sessionId, 5, TimeUnit.SECONDS)
                    .get(5, TimeUnit.SECONDS);
            StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();
            validateStateMachine(stateMachine, sessionId);

            MfaState state = stateMachine.getState().getId();
            optimisticLockManager.updateCachedState(sessionId, state); // 조회 후 캐시 업데이트
            return state;
        } catch (Exception e) {
            log.error("Failed to get current state for session: {} from StateMachine. Error: {}", sessionId, e.getMessage());
            return MfaState.NONE; // 오류 발생 시 안전한 기본 상태 반환
        } finally {
            if (pooled != null) {
                final PooledStateMachine finalPooled = pooled;
                CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId))
                        .exceptionally(ex -> {
                            log.error("Error returning state machine to pool asynchronously for session: {}", sessionId, ex);
                            return null;
                        });
            }
        }
    }

    private boolean isCachedStateValid(String sessionId, MfaState cachedState) {
        // FactorContext 캐시와 비교하여 버전 일관성 확인 로직 등 추가 가능
        // FactorContext context = optimisticLockManager.getCachedContext(sessionId);
        // if (context != null && context.getCurrentState() == cachedState) {
        //     return true;
        // }
        // For now, assume a simple TTL or always re-fetch if not confident
        return true; // 단순화를 위해 항상 유효하다고 가정 (실제로는 TTL 등 필요)
    }


    @Override
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        PooledStateMachine pooled = null;
        try {
            return distributedLockService.executeWithLock("sm:state:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {
                PooledStateMachine currentPooled = null;
                try {
                    currentPooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).get(operationTimeout, TimeUnit.SECONDS);
                    StateMachine<MfaState, MfaEvent> stateMachine = currentPooled.getStateMachine();
                    validateStateMachine(stateMachine, sessionId);

                    // 상태 직접 업데이트 - 주의: 이 방법은 상태 머신의 정상적인 전이 로직을 우회합니다.
                    // 액션을 실행하지 않고 상태만 강제로 변경하므로, 매우 신중하게 사용해야 합니다.
                    // stateMachine.getState().setId(newState); // This is not how SM state is typically changed externally.
                    // Spring StateMachine은 상태를 직접 설정하는 public API를 제공하지 않음.
                    // ExtendedState에 마커를 두어 다음 read 시 반영하거나, 특정 "GOTO" 이벤트를 정의해야 함.
                    // 현재 구현은 ExtendedState 변수를 변경하여 간접적으로 FactorContext에 반영.

                    // 상태를 나타내는 변수를 ExtendedState에 저장
                    stateMachine.getExtendedState().getVariables().put("currentStateName", newState.name());
                    stateMachine.getExtendedState().getVariables().put("_lastStateUpdateType", "STATE_ONLY_UPDATE");
                    stateMachine.getExtendedState().getVariables().put("_lastStateUpdateTimestamp", System.currentTimeMillis());

                    // FactorContext에도 반영 (만약 로드되어 있다면)
                    FactorContext ctx = reconstructFactorContextFromStateMachine(stateMachine);
                    if (ctx != null) {
                        ctx.changeState(newState); // FactorContext 내부 상태 변경
                        storeFactorContextInStateMachine(stateMachine, ctx); // 변경된 FactorContext를 SM에 다시 저장
                    }

                    optimisticLockManager.updateCachedState(sessionId, newState);
                    log.debug("State-only update completed to: {} for session: {}", newState, sessionId);
                    return true;
                } finally {
                    if (currentPooled != null) {
                        CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId))
                                .exceptionally(ex -> {
                                    log.error("Error returning state machine to pool asynchronously for session: {}", sessionId, ex);
                                    return null;
                                });
                    }
                }
            });
        } catch (Exception e) {
            log.error("Failed to update state-only for session: {}", sessionId, e);
            return false;
        }
    }

    private <T> T executeWithRetry(Supplier<T> operation, int maxAttempts, String sessionId, String operationName) {
        Exception lastException = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                T result = operation.get();
                // 작업 성공 시 (예외 없이 반환값이 false일 수도 있음)
                if (result instanceof Boolean && !(Boolean)result) {
                    log.warn("Operation {} attempt {} for session {} returned false, but no exception. Retrying if attempts left.",
                            operationName, attempt, sessionId);
                    // false를 반환한 것이 "실패"인지 아니면 "정상적인 비수락"인지 구분 필요.
                    // 여기서는 일단 재시도 대상으로 간주하나, 이 부분은 비즈니스 로직에 따라 조정 필요.
                    // 만약 false가 최종 실패를 의미하면, 여기서 바로 lastException을 설정하고 루프를 빠져나갈 수 있음.
                    // 현재 구조에서는 boolean 반환하는 operation이 processEventInternal 뿐임.
                }
                return result; // 성공 또는 정상적인 false 반환 시
            } catch (StateMachineProcessingException smpe) { // 재시도 가능한 특정 예외
                lastException = smpe;
                log.warn("Retryable StateMachineProcessingException for operation {} attempt {} for session: {}: {}",
                        operationName, attempt, sessionId, smpe.getMessage());
                if (attempt >= maxAttempts) {
                    log.error("Operation {} failed after {} attempts for session: {}", operationName, maxAttempts, sessionId, smpe);
                    throw smpe; // 최종 실패
                }
                handleRetryDelay(attempt);
            } catch (Exception e) { // 재시도 불가능한 예외
                log.error("Non-retryable exception for operation {} attempt {} for session: {}. Failing immediately.",
                        operationName, attempt, sessionId, e);
                throw new StateMachineException("Non-retryable error in operation " + operationName + " for session " + sessionId, e);
            }
        }
        // 모든 재시도 후에도 실패한 경우 (Boolean false를 반환했거나 마지막 시도에서 예외 발생)
        log.error("Operation {} failed after {} attempts for session: {}. Last exception (if any): {}",
                operationName, maxAttempts, sessionId, lastException != null ? lastException.getMessage() : "N/A");
        if (lastException != null) {
            throw new StateMachineException("Operation " + operationName + " failed after retries for session " + sessionId, lastException);
        } else {
            // 이 경우는 operation이 계속 false를 반환하여 재시도를 모두 소진한 경우.
            // processEventInternal이 false를 반환하는 것은 "이벤트 거부"를 의미.
            // 이것을 예외로 처리할지, 아니면 false로 반환할지는 상위 호출자의 기대에 따름.
            // 현재 sendEvent는 false를 반환하도록 되어 있음.
            return (T) Boolean.FALSE; // Supplier<T>가 Supplier<Boolean>이라고 가정
        }
    }

    private void handleRetryDelay(int attempt) {
        try {
            long delay = Math.min(100L * (1L << Math.min(attempt -1, 5)), 2000L); // Exponential backoff: 100ms, 200ms, 400ms... max 2s
            Thread.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new StateMachineException("Retry delay interrupted", ie);
        }
    }

    private boolean isContextValid(FactorContext context) {
        if (context == null) {
            return false;
        }

        // 기본적인 무결성 검증
        if (context.getMfaSessionId() == null || context.getCurrentState() == null) {
            return false;
        }

        // 터미널 상태면 캐시하지 않음 (상태 변경 가능성 없음)
        if (context.getCurrentState().isTerminal()) {
            return false;
        }

        // 너무 오래된 컨텍스트는 무효 처리
        long contextAge = System.currentTimeMillis() - context.getCreatedAt();
        if (contextAge > TimeUnit.HOURS.toMillis(1)) { // 1시간 초과
            return false;
        }

        return true;
    }


    private boolean isStateMachineHealthy(StateMachine<MfaState, MfaEvent> stateMachine) {
        // PooledStateMachine에서 제공하는 헬스체크로 위임하거나, 여기서 직접 검사
        if (stateMachine == null || stateMachine.hasStateMachineError()) {
            log.warn("StateMachine is null or in error state.");
            return false;
        }
        if (stateMachine.isComplete() && stateMachine.getState() != null && !stateMachine.getState().getId().isTerminal()) {
            log.warn("StateMachine is complete but not in a terminal state ({}). Consider resetting.", stateMachine.getState().getId());
            // 필요시 여기서 SM 리셋 로직 추가 가능 (stop & start)
        }
        return true;
    }

    /**
     * 이벤트 전이 유효성 검증 (상태 머신 구성 기반)
     * @param currentState 현재 상태
     * @param event 검증할 이벤트
     * @param stateMachine 상태 머신 인스턴스
     * @return 전이 가능 여부
     */
    private boolean isValidEventTransition(MfaState currentState, MfaEvent event, StateMachine<MfaState, MfaEvent> stateMachine) {
        if (currentState.isTerminal() && !isTerminalStateOverrideEvent(event)) {
            log.debug("Event {} rejected: State {} is terminal for session {}", event, currentState, stateMachine.getId());
            return false;
        }
        // Spring StateMachine은 내부적으로 getTransitions()를 통해 현재 상태에서 해당 이벤트로의 전이가 있는지 확인합니다.
        // sendEvent()가 false를 반환하면, 유효한 전이가 없거나 가드에 의해 막힌 것입니다.
        // 여기서는 더 상세한 사전 검사를 할 수도 있지만, sendEvent() 결과에 의존하는 것이 더 정확할 수 있습니다.
        // 예를 들어, 상태 머신 설정 자체를 파싱하여 가능한 전이 목록을 만들어두고 여기서 확인할 수 있습니다.
        // 현재는 기본적인 터미널 상태 체크만 수행하고, 나머지는 sendEvent의 결과에 맡깁니다.
        return true;
    }

    private boolean isTerminalStateOverrideEvent(MfaEvent event) {
        // 특정 이벤트는 터미널 상태에서도 처리될 수 있도록 허용 (예: 세션 정리, 강제 종료)
        return event == MfaEvent.SYSTEM_ERROR || event == MfaEvent.SESSION_TIMEOUT;
    }


    private void publishStateChangeAsync(String sessionId, MfaState fromState, MfaState toState, MfaEvent event, Duration duration) {
        CompletableFuture.runAsync(() -> {
            try {
                // Duration이 null일 경우, operationTimings에서 가져오거나 0으로 설정
                Duration actualDuration = duration;
                if (actualDuration == null) {
                    long startTime = operationTimings.getOrDefault(sessionId + ":" + event.name() + ":start", System.currentTimeMillis());
                    actualDuration = Duration.ofMillis(System.currentTimeMillis() - startTime);
                }
                eventPublisher.publishStateChange(sessionId, fromState, toState, event, actualDuration);
            } catch (Exception e) {
                log.warn("Failed to publish state change event asynchronously", e);
            }
        });
    }


    private void publishErrorAsync(String sessionId, MfaState currentState, MfaEvent event, Exception error) {
        CompletableFuture.runAsync(() -> {
            try {
                eventPublisher.publishError(sessionId, currentState, event, error);
            } catch (Exception e) {
                log.warn("Failed to publish error event asynchronously", e);
            }
        });
    }


    private void recordOperationTiming(String operationKeySuffix, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        // 세션 ID와 결합된 키 대신, 순수 operation key 사용 또는 다른 방식으로 집계
        operationTimings.put(operationKeySuffix, duration); // 예: "sendEvent:FACTOR_SELECTED" -> duration

        if (duration > TimeUnit.SECONDS.toMillis(5)) { // 5초 이상 소요된 작업 로깅
            log.warn("Slow operation detected: {} took {}ms", operationKeySuffix, duration);
            // 여기에 성능 알림 이벤트 발행 로직 추가 가능
        }
    }

    private void storeFactorContextInStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext context) {
        if (stateMachine == null || context == null) {
            log.error("Cannot store FactorContext: StateMachine or FactorContext is null. SessionId from context: {}", context != null ? context.getMfaSessionId() : "N/A");
            return; // 또는 예외 발생
        }
        String sessionId = context.getMfaSessionId();
        log.debug("Storing FactorContext into StateMachine for session: {}. Current SM State: {}, Context State: {}",
                sessionId, stateMachine.getState() != null ? stateMachine.getState().getId() : "null", context.getCurrentState());

        if (stateMachine.getState() == null) {
            log.warn("Attempting to store FactorContext in a non-started/error StateMachine for session: {}. Validating/Starting SM.", sessionId);
            validateStateMachine(stateMachine, sessionId); // SM 시작 보장
        }

        ExtendedState extendedState = stateMachine.getExtendedState();
        if (extendedState == null) {
            log.error("ExtendedState is null for StateMachine of session: {}. Cannot store FactorContext.", sessionId);
            throw new IllegalStateException("ExtendedState is null, cannot store FactorContext for session: " + sessionId);
        }

        Map<Object, Object> stateMachineVariables = extendedState.getVariables();
        if (stateMachineVariables == null) {
            log.error("ExtendedState variables map is null for StateMachine of session: {}. This is highly unusual.", sessionId);
            // 이 경우, SM 내부 상태가 심각하게 손상된 것일 수 있음.
            // 새 맵을 할당하려고 시도해 볼 수 있으나, 근본 원인 파악이 중요.
            // extendedState.setVariables(new HashMap<>()); // SM 구현에 따라 작동하지 않을 수 있음
            throw new IllegalStateException("ExtendedState variables map is null, cannot store FactorContext for session: " + sessionId);
        }

        Map<Object, Object> contextVariablesToStore = factorContextAdapter.toStateMachineVariables(context);

        // 버전 관리 및 충돌 방지를 위해 OptimisticLockManager 사용 고려
        // 여기서는 직접 덮어쓰지만, 실제로는 버전 체크 후 업데이트가 더 안전
        try {
            // 기존 변수를 모두 지우고 새 변수로 대체하는 것이 아니라,
            // FactorContextStateAdapter가 반환하는 변수들로 업데이트(putAll)하는 것이 일반적.
            // 만약 SM의 ExtendedState가 특정 키에 대해 이전 값을 유지해야 한다면, putAll은 적절.
            // FactorContext가 상태의 유일한 원천이라면 clear() 후 putAll()도 가능.
            // 현재 toStateMachineVariables가 모든 필요한 변수를 반환한다고 가정하고 putAll 사용.
            stateMachineVariables.putAll(contextVariablesToStore);

            log.debug("Successfully stored/updated {} variables in StateMachine for session: {} based on FactorContext version {}",
                    contextVariablesToStore.size(), sessionId, context.getVersion());
        } catch (Exception e) {
            log.error("Failed to putAll variables into StateMachine's ExtendedState for session: {}", sessionId, e);
            throw new StateMachineException("Failed to update state machine variables for session " + sessionId, e);
        }
    }


    private FactorContext reconstructFactorContextFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        if (stateMachine == null) {
            log.error("Cannot reconstruct FactorContext: StateMachine is null.");
            return createDummyErrorContext("UnknownSession-NullSM");
        }
        if (stateMachine.getExtendedState() == null || stateMachine.getExtendedState().getVariables() == null) {
            log.error("Cannot reconstruct FactorContext: ExtendedState or its variables are null for SM ID: {}", stateMachine.getId());
            return createDummyErrorContext(stateMachine.getId() != null ? stateMachine.getId() : "UnknownSession-NullExtendedState");
        }
        // FactorContextStateAdapter를 통해 재구성
        return factorContextAdapter.reconstructFromStateMachine(stateMachine);
    }

    private FactorContext createDummyErrorContext(String sessionId) {
        Authentication dummyAuth = new AnonymousAuthenticationToken("key", "errorUser-" + sessionId, Collections.singletonList(new SimpleGrantedAuthority("ROLE_NONE")));
        return new FactorContext(sessionId, dummyAuth, MfaState.MFA_SYSTEM_ERROR, "error_flow");
    }


    private void mergeBusinessDataOnly(FactorContext targetContext, FactorContext sourceContext) {
        if (targetContext == null || sourceContext == null) {
            log.warn("Cannot merge contexts: one or both contexts are null.");
            return;
        }
        // 선택적으로 비즈니스 관련 중요 데이터만 sourceContext에서 targetContext로 복사/병합
        // 예: 사용자가 UI에서 입력한 값, 특정 단계에서 수집된 정보 등
        // 상태(currentState), 버전(version) 등은 StateMachine이 관리하므로 직접 복사하지 않음.
        // 여기서는 sourceContext의 'attributes'를 targetContext로 병합하는 예시
        sourceContext.getAttributes().forEach((key, value) -> {
            if (isBusinessAttribute(key)) { // 시스템 속성이 아닌 사용자 정의 속성만 병합
                targetContext.setAttribute(key, value);
            }
        });
        // 추가적으로 필요한 필드 병합 (예: lastError, retryCount 등 FactorContext의 직접 필드)
        if (sourceContext.getLastError() != null) {
            targetContext.setLastError(sourceContext.getLastError());
        }
        // retryCount는 SM에서 관리될 수 있으므로 주의. 여기서는 일단 병합하지 않음.
        // targetContext.setRetryCount(Math.max(targetContext.getRetryCount(), sourceContext.getRetryCount()));
        log.debug("Merged business data from source context (session {}) to target context (session {})",
                sourceContext.getMfaSessionId(), targetContext.getMfaSessionId());
    }


    private void syncFactorContextFromStateMachine(FactorContext applicationContext, FactorContext authoritativeSmContext) {
        if (applicationContext == null || authoritativeSmContext == null) {
            log.warn("Cannot sync contexts: one or both contexts are null.");
            return;
        }
        // State Machine의 FactorContext (authoritativeSmContext) 내용을
        // 애플리케이션 레벨의 FactorContext (applicationContext)로 동기화
        applicationContext.changeState(authoritativeSmContext.getCurrentState());
        applicationContext.setVersion(authoritativeSmContext.getVersion()); // 버전 직접 설정
        applicationContext.setCurrentProcessingFactor(authoritativeSmContext.getCurrentProcessingFactor());
        applicationContext.setCurrentStepId(authoritativeSmContext.getCurrentStepId());
        // currentFactorOptions는 일반적으로 SM내에 직접 저장하지 않고, currentStepId를 통해 FlowConfig에서 조회
        // 여기서는 authoritativeSmContext에 이미 올바른 옵션이 있다고 가정.
        applicationContext.setCurrentFactorOptions(authoritativeSmContext.getCurrentFactorOptions());
        applicationContext.setMfaRequiredAsPerPolicy(authoritativeSmContext.isMfaRequiredAsPerPolicy());
        applicationContext.setRetryCount(authoritativeSmContext.getRetryCount());
        applicationContext.setLastError(authoritativeSmContext.getLastError());
        applicationContext.setLastActivityTimestamp(authoritativeSmContext.getLastActivityTimestamp());

        // Collections and Maps
        applicationContext.getCompletedFactors().clear();
        authoritativeSmContext.getCompletedFactors().forEach(applicationContext::addCompletedFactor);

        applicationContext.getRegisteredMfaFactors().clear(); // Assuming this method clears internal list
        if (authoritativeSmContext.getRegisteredMfaFactors() != null) {
            applicationContext.setRegisteredMfaFactors(new ArrayList<>(authoritativeSmContext.getRegisteredMfaFactors()));
        }


        applicationContext.getFactorAttemptCounts().clear();
        if (authoritativeSmContext.getFactorAttemptCounts() != null) {
            authoritativeSmContext.getFactorAttemptCounts().forEach((factor, count) -> {
                for(int i=0; i < count; i++) applicationContext.incrementAttemptCount(factor);
            });
        }


        applicationContext.getMfaAttemptHistory().clear();
        if (authoritativeSmContext.getMfaAttemptHistory() != null) {
            authoritativeSmContext.getMfaAttemptHistory().forEach(attempt ->
                    applicationContext.recordAttempt(attempt.getFactorType(), attempt.isSuccess(), attempt.getDetail())
            );
        }


        applicationContext.getAttributes().clear();
        if (authoritativeSmContext.getAttributes() != null) {
            authoritativeSmContext.getAttributes().forEach(applicationContext::setAttribute);
        }

        log.debug("Application FactorContext (session {}) synced from StateMachine's context. New state: {}, version: {}",
                applicationContext.getMfaSessionId(), applicationContext.getCurrentState(), applicationContext.getVersion());
    }


    private boolean isBusinessAttribute(String key) {
        // StateMachine이 직접 관리하는 필드나 시스템 내부용 속성을 제외
        return !(key.startsWith("_") ||
                key.equals("mfaSessionId") ||
                key.equals("username") ||
                key.equals("flowTypeName") ||
                key.equals("currentStateName") ||
                key.equals("version") ||
                key.equals("primaryAuthentication") ||
                key.equals("currentProcessingFactorName") ||
                key.equals("currentStepId") ||
                key.equals("retryCount") ||
                key.equals("lastError") ||
                key.equals("mfaRequiredAsPerPolicy") ||
                key.equals("createdAt") ||
                key.equals("lastActivityTimestamp")
                // Add other system-managed keys if necessary
        );
    }

    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context, HttpServletRequest request) {
        MessageBuilder<MfaEvent> builder = MessageBuilder.withPayload(event);
        if (context != null) {
            builder.setHeader("mfaSessionId", context.getMfaSessionId());
            builder.setHeader("username", context.getUsername());
            builder.setHeader("factorContextVersion", context.getVersion());
            if (context.getPrimaryAuthentication() != null) {
                builder.setHeader("authentication", context.getPrimaryAuthentication());
            }
        }
        if (request != null) {
            builder.setHeader("httpRequest", request); // For potential use in actions/guards
        }
        builder.setHeader("eventTimestamp", System.currentTimeMillis());
        return builder.build();
    }

    private ExecutorService getSessionExecutor(String sessionId) {
        // 세션별로 고유한 단일 스레드 실행자 사용, 순차적 이벤트 처리 보장
        return sessionExecutors.computeIfAbsent(sessionId, k -> {
            ThreadFactory threadFactory = r -> {
                Thread thread = new Thread(r, "MFA-SM-Session-" + sessionId.substring(0, Math.min(8, sessionId.length())));
                thread.setDaemon(true); // 애플리케이션 종료 방해하지 않도록
                return thread;
            };
            return Executors.newSingleThreadExecutor(threadFactory);
        });
    }

    private boolean isCircuitClosed() {
        CircuitState currentState = circuitState.get();
        if (currentState == CircuitState.OPEN) {
            if (System.currentTimeMillis() - lastFailureTime > (long)circuitBreakerTimeout * 1000) {
                // HALF_OPEN 상태로 변경 시도 (단 한 번만 성공하도록 compareAndSet 사용)
                if (circuitState.compareAndSet(CircuitState.OPEN, CircuitState.HALF_OPEN)) {
                    log.info("Circuit breaker transitioned to HALF_OPEN for MFA State Machine Service.");
                    // HALF_OPEN에서는 첫 번째 요청을 허용
                }
                // 여전히 OPEN이면 false 반환, HALF_OPEN으로 변경되었으면 true 반환
                return circuitState.get() == CircuitState.HALF_OPEN;
            }
            return false; // OPEN 상태이고, 타임아웃 전
        }
        return true; // CLOSED 또는 HALF_OPEN 상태
    }

    private void onSuccess() {
        // 성공 카운터는 필요시 추가
        // successCount.incrementAndGet();
        // HALF_OPEN 상태에서 성공하면 CLOSED로 변경
        if (circuitState.compareAndSet(CircuitState.HALF_OPEN, CircuitState.CLOSED)) {
            failureCount.set(0); // 실패 카운터 리셋
            log.info("Circuit breaker is now CLOSED for MFA State Machine Service after successful operation in HALF_OPEN state.");
        }
        // CLOSED 상태에서는 별도 작업 없음
    }

    private void onFailure() {
        lastFailureTime = System.currentTimeMillis();
        int currentFailures = failureCount.incrementAndGet();

        CircuitState currentState = circuitState.get();
        if (currentState == CircuitState.HALF_OPEN) {
            // HALF_OPEN 상태에서 실패하면 즉시 OPEN으로 변경
            circuitState.set(CircuitState.OPEN);
            log.error("Circuit breaker re-opened due to failure in HALF_OPEN state for MFA State Machine Service. Current failures: {}", currentFailures);
        } else if (currentState == CircuitState.CLOSED && currentFailures >= failureThreshold) {
            // CLOSED 상태에서 실패 임계값 도달 시 OPEN으로 변경
            if (circuitState.compareAndSet(CircuitState.CLOSED, CircuitState.OPEN)) {
                log.error("Circuit breaker OPENED for MFA State Machine Service after {} consecutive failures.", currentFailures);
            }
        }
    }

    public Map<String, Object> getHealthMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("circuitState", circuitState.get().name());
        metrics.put("activeOperations", activeOperations.get());
        metrics.put("failureCount", failureCount.get());
        metrics.put("activeSessionExecutors", sessionExecutors.size());
        metrics.put("lastFailureTimeMillis", lastFailureTime);
        metrics.put("operationTimingsSnapshot", new HashMap<>(operationTimings)); // 동시성 문제 피하기 위해 복사본
        return metrics;
    }

    public void shutdown() {
        log.info("Shutting down MfaStateMachineService...");
        sessionExecutors.forEach((id, executor) -> {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        });
        sessionExecutors.clear();
        stateMachinePool.shutdown();
        log.info("MfaStateMachineService shutdown complete.");
    }

    private enum CircuitState {
        CLOSED, OPEN, HALF_OPEN
    }

    public static class StateMachineException extends RuntimeException {
        public StateMachineException(String message) {
            super(message);
        }
        public StateMachineException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * StateMachine 처리 중 발생하는 특정 예외
     */
    public static class StateMachineProcessingException extends StateMachineException {
        private final MfaState stateAtError;
        private final MfaEvent eventAttempted;

        public StateMachineProcessingException(String message, Throwable cause, MfaState stateAtError, MfaEvent eventAttempted) {
            super(message, cause);
            this.stateAtError = stateAtError;
            this.eventAttempted = eventAttempted;
        }

        public MfaState getStateAtError() {
            return stateAtError;
        }

        public MfaEvent getEventAttempted() {
            return eventAttempted;
        }
    }
}