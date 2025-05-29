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
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * 완전 일원화된 MFA State Machine 서비스 - 최종 개선판
 * 개선사항:
 * - 이벤트 처리 최적화: 불필요한 락 경합 최소화
 * - 성능 향상: 캐시 및 배치 처리 활용
 * - 안정성 강화: Circuit Breaker 및 재시도 로직 개선
 * - 모니터링 개선: 상세한 메트릭 및 로깅
 */
@Slf4j
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final StateMachinePool stateMachinePool;
    private final FactorContextStateAdapter factorContextAdapter;
    private final MfaEventPublisher eventPublisher;
    private final RedisDistributedLockService distributedLockService;
    private final OptimisticLockManager optimisticLockManager;

    // 개선: 세션별 실행자 관리
    private final ConcurrentHashMap<String, ExecutorService> sessionExecutors = new ConcurrentHashMap<>();

    // 개선: Circuit Breaker 상태 관리
    private final AtomicReference<CircuitState> circuitState = new AtomicReference<>(CircuitState.CLOSED);
    private volatile long lastFailureTime = 0;
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicInteger successCount = new AtomicInteger(0);

    // 개선: 성능 메트릭
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

    /**
     * 개선: 성능 최적화된 State Machine 초기화
     */
    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        long startTime = System.currentTimeMillis();

        log.info("Initializing State Machine for session: {}", sessionId);

        if (!isCircuitClosed()) {
            throw new StateMachineException("Circuit breaker is open - system protection activated");
        }

        activeOperations.incrementAndGet();
        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                distributedLockService.executeWithLock("sm:init:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {

                    PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                            sessionId, operationTimeout, TimeUnit.SECONDS
                    ).get(operationTimeout, TimeUnit.SECONDS);

                    try {
                        StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                        if (!isStateMachineHealthy(stateMachine)) {
                            throw new StateMachineException("State Machine health check failed");
                        }

                        // State Machine 시작
                        boolean needsStart = !stateMachine.isComplete() &&
                                (stateMachine.getState() == null ||
                                        stateMachine.getExtendedState() == null ||
                                        stateMachine.getExtendedState().getVariables() == null);

                        if (needsStart) {
                            log.debug("Starting State Machine synchronously for session: {}", sessionId);
                            stateMachine.start();
                            Thread.sleep(300);

                            if (stateMachine.getExtendedState() == null ||
                                    stateMachine.getExtendedState().getVariables() == null) {
                                Thread.sleep(200);
                                if (stateMachine.getExtendedState() == null ||
                                        stateMachine.getExtendedState().getVariables() == null) {
                                    throw new StateMachineException("ExtendedState not properly initialized after start");
                                }
                            }
                        }

                        // FactorContext를 State Machine에 저장
                        storeFactorContextInStateMachine(stateMachine, context);

                        // PRIMARY_AUTH_SUCCESS 이벤트 전송
                        Message<MfaEvent> message = createEventMessage(
                                MfaEvent.PRIMARY_AUTH_SUCCESS, context, request);

                        boolean accepted = stateMachine.sendEvent(message);

                        if (accepted) {
                            MfaState newState = stateMachine.getState().getId();

                            // FactorContext 상태 업데이트
                            context.changeState(newState);
                            context.incrementVersion();

                            // ExtendedState에 현재 상태 명시적 저장
                            stateMachine.getExtendedState().getVariables().put("currentState", newState.name());
                            stateMachine.getExtendedState().getVariables().put("_lastStateUpdate", System.currentTimeMillis());

                            // 업데이트된 FactorContext를 State Machine에 다시 저장
                            storeFactorContextInStateMachine(stateMachine, context);

                            publishStateChangeAsync(sessionId, MfaState.NONE, newState, MfaEvent.PRIMARY_AUTH_SUCCESS);
                            onSuccess();

                            log.info("State Machine initialized successfully for session: {}. State: NONE -> {}",
                                    sessionId, newState);
                        } else {
                            throw new StateMachineException("Failed to process PRIMARY_AUTH_SUCCESS event");
                        }
                    } finally {
                        CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId));
                    }

                    return null;
                });
            } catch (Exception e) {
                onFailure();
                log.error("Failed to initialize State Machine for session: {}", sessionId, e);
                throw new StateMachineException("State Machine initialization failed", e);
            } finally {
                activeOperations.decrementAndGet();
                recordOperationTiming("initialize", startTime);
            }
        }, executor);

        try {
            future.get(operationTimeout, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new StateMachineException("State Machine initialization timeout", e);
        } catch (Exception e) {
            throw new StateMachineException("State Machine initialization failed", e);
        }
    }

    /**
     * 동기식으로 State Machine 시작 보장
     */
    private void ensureStateMachineStartedSync(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) {
        // State Machine이 시작되었는지 확인
        if (stateMachine.getState() == null || stateMachine.getExtendedState() == null) {
            log.info("Starting State Machine synchronously for session: {}", sessionId);

            try {
                // 동기식 start() 사용
                stateMachine.start();

                // 초기화 완료 대기
                int maxRetries = 10;
                int retryCount = 0;

                while (retryCount < maxRetries) {
                    Thread.sleep(100);

                    if (stateMachine.getState() != null &&
                            stateMachine.getExtendedState() != null &&
                            stateMachine.getExtendedState().getVariables() != null) {
                        log.debug("State Machine started successfully after {} retries", retryCount);
                        return;
                    }

                    retryCount++;
                }

                // 최종 확인
                if (stateMachine.getState() == null) {
                    throw new IllegalStateException("State is still null after start");
                }

                if (stateMachine.getExtendedState() == null ||
                        stateMachine.getExtendedState().getVariables() == null) {
                    throw new IllegalStateException("ExtendedState not initialized after start");
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while starting State Machine", e);
            } catch (Exception e) {
                log.error("Failed to start State Machine for session: {}", sessionId, e);
                throw new RuntimeException("State Machine start failed", e);
            }
        }
    }

    /**
     * 동기식 State Machine 검증
     */
    private void validateStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) {
        if (stateMachine == null) {
            throw new IllegalStateException("Borrowed null StateMachine for session: " + sessionId);
        }

        // hasStateMachineError() 메서드로 에러 여부만 확인 가능
        if (stateMachine.hasStateMachineError()) {
            log.error("StateMachine has error for session: {}", sessionId);

            // 에러 상태에서 복구 - stop/start로 리셋
            try {
                stateMachine.stop();
                Thread.sleep(100);
                stateMachine.start();
                Thread.sleep(100);

                // 리셋 후에도 에러가 있는지 확인
                if (stateMachine.hasStateMachineError()) {
                    throw new IllegalStateException("StateMachine still in error state after reset");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted during StateMachine reset", e);
            }
        }

        // 완료 상태 확인
        if (stateMachine.isComplete()) {
            log.warn("Borrowed completed StateMachine for session: {}, restarting", sessionId);
            try {
                stateMachine.stop();
                Thread.sleep(50);
                stateMachine.start();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 개선: 배치 처리 및 재시도 로직이 적용된 이벤트 전송
     */
    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        long startTime = System.currentTimeMillis();

        log.debug("Sending optimized event {} for session: {}", event, sessionId);

        if (!isCircuitClosed()) {
            log.error("Circuit breaker is open, rejecting event: {}", event);
            return false;
        }

        activeOperations.incrementAndGet();
        ExecutorService executor = getSessionExecutor(sessionId);

        CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
            return executeWithRetry(() -> processEventInternal(event, context, request),
                    maxRetryAttempts, sessionId, event.name());
        }, executor);

        try {
            boolean result = future.get(operationTimeout, TimeUnit.SECONDS);
            if (result) {
                onSuccess();
            } else {
                onFailure();
            }
            return result;
        } catch (TimeoutException e) {
            future.cancel(true);
            log.error("Event processing timeout for session: {} event: {}", sessionId, event);
            onFailure();
            return false;
        } catch (Exception e) {
            log.error("Event processing failed for session: {} event: {}", sessionId, event, e);
            onFailure();
            return false;
        } finally {
            activeOperations.decrementAndGet();
            recordOperationTiming("sendEvent", startTime);
        }
    }

    /**
     * 개선: 내부 이벤트 처리 로직 (재시도 가능)
     */
    private boolean processEventInternal(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();

        try {
            return distributedLockService.executeWithLock("sm:event:" + sessionId, Duration.ofSeconds(operationTimeout), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, operationTimeout, TimeUnit.SECONDS
                ).get(operationTimeout, TimeUnit.SECONDS);

                try {
                    StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                    // State Machine 건강성 확인
                    if (!isStateMachineHealthy(stateMachine)) {
                        log.warn("State Machine health check failed for session: {}", sessionId);
                        return false;
                    }

                    MfaState currentState = stateMachine.getState().getId();

                    // 이벤트 유효성 사전 검증
                    if (!isValidEventTransition(currentState, event)) {
                        log.warn("Invalid event transition: {} -> {} for session: {}", currentState, event, sessionId);
                        return false;
                    }

                    // 최신 FactorContext 재구성 및 병합
                    FactorContext latestContext = reconstructFactorContextFromStateMachine(stateMachine);
                    mergeBusinessDataOnly(latestContext, context);
                    storeFactorContextInStateMachine(stateMachine, latestContext);

                    // 이벤트 전송
                    Message<MfaEvent> message = createEventMessage(event, latestContext, request);
                    boolean accepted = stateMachine.sendEvent(message);

                    if (accepted) {
                        MfaState newState = stateMachine.getState().getId();
                        updateFactorContextFromStateMachine(latestContext, stateMachine);
                        syncFactorContextFromStateMachine(context, latestContext);

                        // 개선: 비동기 이벤트 발행
                        publishStateChangeAsync(sessionId, currentState, newState, event);

                        log.debug("Event {} processed successfully: {} -> {} for session: {}",
                                event, currentState, newState, sessionId);
                    } else {
                        log.warn("Event {} rejected in state {} for session: {}", event, currentState, sessionId);
                    }

                    return accepted;

                } finally {
                    CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId));
                }
            });
        } catch (Exception e) {
            log.error("Failed to process event {} for session: {}", event, sessionId, e);
            publishErrorAsync(sessionId, context.getCurrentState(), event, e);
            return false;
        }
    }

    @Override
    public FactorContext getFactorContext(String sessionId) {
        // 캐시 확인 로직 개선
        FactorContext cachedContext = optimisticLockManager.getCachedContext(sessionId);
        if (cachedContext != null) {
            // 캐시된 컨텍스트의 유효성 검증
            if (isContextValid(cachedContext)) {
                log.trace("Retrieved valid FactorContext from cache for session: {}", sessionId);
                return cachedContext;
            } else {
                // 유효하지 않은 캐시 제거
                optimisticLockManager.invalidateContextCache(sessionId);
                log.debug("Invalidated stale cached context for session: {}", sessionId);
            }
        }

        try {
            return distributedLockService.executeWithLock("sm:context:" + sessionId, Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 5, TimeUnit.SECONDS
                ).get(5, TimeUnit.SECONDS);

                try {
                    FactorContext context = reconstructFactorContextFromStateMachine(pooled.getStateMachine());

                    if (context != null) {
                        // 상태와 컨텍스트 모두 캐시에 저장
                        optimisticLockManager.updateCachedState(sessionId, context.getCurrentState());
                        optimisticLockManager.updateCachedContext(sessionId, context);

                        log.debug("FactorContext loaded and cached for session: {}", sessionId);
                    }

                    return context;
                } finally {
                    CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId));
                }
            });
        } catch (Exception e) {
            log.error("Failed to get FactorContext for session: {}", sessionId, e);
            return null;
        }
    }

    /**
     * 캐시된 컨텍스트 유효성 검증
     */
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

    /**
     * saveFactorContext 메서드도 캐시 업데이트 포함
     */
    @Override
    public void saveFactorContext(FactorContext context) {
        try {
            distributedLockService.executeWithLock("sm:save:" + context.getMfaSessionId(), Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        context.getMfaSessionId(), 5, TimeUnit.SECONDS
                ).get(5, TimeUnit.SECONDS);

                try {
                    storeFactorContextInStateMachine(pooled.getStateMachine(), context);

                    // 저장과 동시에 캐시 업데이트
                    optimisticLockManager.updateCachedContext(context.getMfaSessionId(), context);
                    optimisticLockManager.updateCachedState(context.getMfaSessionId(), context.getCurrentState());

                    log.trace("FactorContext saved and cached for session: {}", context.getMfaSessionId());
                } finally {
                    CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(context.getMfaSessionId()));
                }

                return null;
            });
        } catch (Exception e) {
            log.error("Failed to save FactorContext for session: {}", context.getMfaSessionId(), e);
        }
    }

    /**
     * releaseStateMachine에서 캐시도 정리
     */
    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing optimized State Machine for session: {}", sessionId);

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
                // 컨텍스트 캐시도 정리
                optimisticLockManager.invalidateContextCache(sessionId);
                operationTimings.remove(sessionId);

                eventPublisher.publishCustomEvent("SESSION_CLEANUP", Map.of(
                        "sessionId", sessionId,
                        "timestamp", System.currentTimeMillis(),
                        "activeOperations", activeOperations.get()
                ));
            } catch (Exception e) {
                log.error("Error releasing optimized State Machine for session: {}", sessionId, e);
            }
        });
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        // 캐시 우선 확인
        MfaState cachedState = optimisticLockManager.getCachedState(sessionId);
        if (cachedState != null) {
            return cachedState;
        }

        try {
            return distributedLockService.executeWithLock("sm:state:" + sessionId, Duration.ofSeconds(5), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 5, TimeUnit.SECONDS
                ).get(5, TimeUnit.SECONDS);

                try {
                    MfaState state = pooled.getStateMachine().getState().getId();
                    optimisticLockManager.updateCachedState(sessionId, state);
                    return state;
                } finally {
                    CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId));
                }
            });
        } catch (Exception e) {
            log.error("Failed to get current state for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    @Override
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        try {
            return distributedLockService.executeWithLock("sm:state:" + sessionId, Duration.ofSeconds(3), () -> {

                PooledStateMachine pooled = stateMachinePool.borrowStateMachine(
                        sessionId, 3, TimeUnit.SECONDS
                ).get(3, TimeUnit.SECONDS);

                try {
                    StateMachine<MfaState, MfaEvent> stateMachine = pooled.getStateMachine();

                    // 상태 직접 업데이트
                    stateMachine.getExtendedState().getVariables().put("currentState", newState.name());
                    stateMachine.getExtendedState().getVariables().put("_lastStateUpdate", System.currentTimeMillis());

                    // 캐시 업데이트
                    optimisticLockManager.updateCachedState(sessionId, newState);

                    log.debug("State-only update completed: {} for session: {}", newState, sessionId);
                    return true;
                } finally {
                    CompletableFuture.runAsync(() -> stateMachinePool.returnStateMachine(sessionId));
                }
            });
        } catch (Exception e) {
            log.error("Failed to update state for session: {}", sessionId, e);
            return false;
        }
    }

    /**
     * 개선: 재시도 로직 실행
     */
    private <T> T executeWithRetry(Supplier<T> operation, int maxAttempts, String sessionId, String operationName) {
        Exception lastException = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return operation.get();
            } catch (Exception e) {
                lastException = e;
                log.warn("Operation {} attempt {} failed for session: {}: {}",
                        operationName, attempt, sessionId, e.getMessage());

                if (attempt < maxAttempts) {
                    try {
                        // 지수 백오프
                        long delay = Math.min(1000 * (1L << (attempt - 1)), 5000);
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }

        log.error("Operation {} failed after {} attempts for session: {}",
                operationName, maxAttempts, sessionId, lastException);
        throw new RuntimeException("Operation failed after retries", lastException);
    }

    /**
     * 개선: State Machine 건강성 검사
     */
    private boolean isStateMachineHealthy(StateMachine<MfaState, MfaEvent> stateMachine) {
        try {
            if (stateMachine == null) {
                log.error("StateMachine is null");
                return false;
            }

            if (stateMachine.hasStateMachineError()) {
                log.error("StateMachine has error");
                return false;
            }

            // ExtendedState 검증 추가
            ExtendedState extendedState = stateMachine.getExtendedState();
            if (extendedState == null) {
                log.warn("StateMachine ExtendedState is null - may need initialization");
                // ExtendedState가 null이어도 시작 후 초기화될 수 있으므로 true 반환
                return true;
            }

            return true;
        } catch (Exception e) {
            log.warn("State Machine health check exception", e);
            return false;
        }
    }

    /**
     * 개선: 이벤트 전이 유효성 검증
     */
    private boolean isValidEventTransition(MfaState currentState, MfaEvent event) {
        // 터미널 상태에서는 관리 이벤트만 허용
        if (currentState.isTerminal()) {
            return event == MfaEvent.SYSTEM_ERROR;  // 터미널에서는 시스템 에러만
        }

        // SYSTEM_ERROR는 터미널이 아닌 모든 상태에서 가능
        if (event == MfaEvent.SYSTEM_ERROR) {
            return !currentState.isTerminal();
        }

        // SESSION_TIMEOUT은 특정 상태에서만 가능
        if (event == MfaEvent.SESSION_TIMEOUT) {
            return currentState == MfaState.AWAITING_FACTOR_SELECTION ||
                    currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                    currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION||
                    currentState == MfaState.FACTOR_VERIFICATION_PENDING;
        }

        // USER_ABORTED_MFA 추가
        if (event == MfaEvent.USER_ABORTED_MFA) {
            return currentState == MfaState.AWAITING_FACTOR_SELECTION ||
                    currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                    currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
        }

        // 상태별 허용 이벤트
        return switch (currentState) {
            case NONE ->
                    event == MfaEvent.PRIMARY_AUTH_SUCCESS;

            case PRIMARY_AUTHENTICATION_COMPLETED ->
                    event == MfaEvent.MFA_NOT_REQUIRED ||
                            event == MfaEvent.MFA_REQUIRED_SELECT_FACTOR ||
                            event == MfaEvent.MFA_CONFIGURATION_REQUIRED;

            case AWAITING_FACTOR_SELECTION ->
                    event == MfaEvent.FACTOR_SELECTED ||
                            event == MfaEvent.USER_ABORTED_MFA;

            case AWAITING_FACTOR_CHALLENGE_INITIATION ->
                    event == MfaEvent.INITIATE_CHALLENGE ||
                            event == MfaEvent.USER_ABORTED_MFA;

            /*case FACTOR_CHALLENGE_INITIATED ->
                    event == MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY ||
                            event == MfaEvent.CHALLENGE_INITIATION_FAILED;*/

            case FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ->
                    event == MfaEvent.SUBMIT_FACTOR_CREDENTIAL ||
                            event == MfaEvent.USER_ABORTED_MFA ||
                            event == MfaEvent.CHALLENGE_TIMEOUT;

            case FACTOR_VERIFICATION_PENDING ->
                    event == MfaEvent.FACTOR_VERIFIED_SUCCESS ||
                            event == MfaEvent.FACTOR_VERIFICATION_FAILED ||
                            event == MfaEvent.RETRY_LIMIT_EXCEEDED;

            case FACTOR_VERIFICATION_COMPLETED ->
                    event == MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED;

            case ALL_FACTORS_COMPLETED ->
                    event == MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN;

            case MFA_RETRY_LIMIT_EXCEEDED ->
                    event == MfaEvent.SYSTEM_ERROR;

            case MFA_CONFIGURATION_REQUIRED ->
                    false; // 이 상태에서는 추가 전이 없음

            default -> {
                log.warn("Unhandled state in event transition validation: {} for event: {}",
                        currentState, event);
                yield false; // 안전을 위해 기본값은 false
            }
        };
    }

    /**
     * 개선: 비동기 상태 변경 이벤트 발행
     */
    private void publishStateChangeAsync(String sessionId, MfaState fromState, MfaState toState, MfaEvent event) {
        CompletableFuture.runAsync(() -> {
            try {
                Duration duration = Duration.ofMillis(System.currentTimeMillis() -
                        operationTimings.getOrDefault(sessionId + ":" + event.name(), System.currentTimeMillis()));
                eventPublisher.publishStateChange(sessionId, fromState, toState, event, duration);
            } catch (Exception e) {
                log.warn("Failed to publish state change event asynchronously", e);
            }
        });
    }

    /**
     * 개선: 비동기 오류 이벤트 발행
     */
    private void publishErrorAsync(String sessionId, MfaState currentState, MfaEvent event, Exception error) {
        CompletableFuture.runAsync(() -> {
            try {
                eventPublisher.publishError(sessionId, currentState, event, error);
            } catch (Exception e) {
                log.warn("Failed to publish error event asynchronously", e);
            }
        });
    }

    /**
     * 개선: 작업 시간 기록
     */
    private void recordOperationTiming(String operation, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        operationTimings.put(operation, duration);

        if (duration > 1000) { // 1초 이상 소요된 작업 로깅
            log.warn("Slow operation detected: {} took {}ms", operation, duration);
        }
    }

    private void storeFactorContextInStateMachine(StateMachine<MfaState, MfaEvent> stateMachine,
                                                  FactorContext context) {
        if (stateMachine == null || context == null) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }

        String sessionId = context.getMfaSessionId();
        log.debug("Storing FactorContext for session: {}", sessionId);

        // State Machine 초기화 확인
        if (stateMachine.getState() == null) {
            log.warn("StateMachine state is null, starting it for session: {}", sessionId);
            stateMachine.start();

            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while starting StateMachine", e);
            }
        }

        // ExtendedState 확인
        ExtendedState extendedState = stateMachine.getExtendedState();
        if (extendedState == null) {
            // 재시작 시도
            try {
                stateMachine.stop();
                Thread.sleep(100);
                stateMachine.start();
                Thread.sleep(300);

                extendedState = stateMachine.getExtendedState();
                if (extendedState == null) {
                    throw new IllegalStateException("Cannot initialize ExtendedState");
                }
            } catch (Exception e) {
                throw new IllegalStateException("Failed to initialize ExtendedState", e);
            }
        }

        // Variables 가져오기
        Map<Object, Object> stateVariables = extendedState.getVariables();
        if (stateVariables == null) {
            throw new IllegalStateException("ExtendedState variables is null");
        }

        // Adapter를 통한 변환
        Map<Object, Object> variables;
        try {
            variables = factorContextAdapter.toStateMachineVariables(context);
            if (variables == null) {
                variables = new HashMap<>();
            }
        } catch (Exception e) {
            log.error("Error in adapter for session: {}", sessionId, e);
            variables = new HashMap<>();
            variables.put("mfaSessionId", sessionId);
        }

        // 메타데이터 추가
        variables.put("_lastUpdated", System.currentTimeMillis());
        variables.put("_version", context.getVersion());
        variables.put("_stateHash", context.calculateStateHash());
        variables.put("_storageType", "UNIFIED_STATE_MACHINE");

        try {
            stateVariables.clear();
            stateVariables.putAll(variables);

            log.debug("Successfully stored {} variables in StateMachine for session: {}",
                    stateVariables.size(), sessionId);

        } catch (UnsupportedOperationException e) {
            log.error("Variables map is immutable for session: {}", sessionId);
            throw new IllegalStateException("Cannot modify ExtendedState variables - immutable map", e);
        } catch (Exception e) {
            log.error("Failed to update variables for session: {}", sessionId, e);
            throw new IllegalStateException("ExtendedState variables operation failed", e);
        }
    }

    private FactorContext reconstructFactorContextFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        return factorContextAdapter.reconstructFromStateMachine(stateMachine);
    }

    private void updateFactorContextFromStateMachine(FactorContext context,
                                                     StateMachine<MfaState, MfaEvent> stateMachine) {
        factorContextAdapter.updateFactorContext(stateMachine, context);
    }

    private void mergeBusinessDataOnly(FactorContext target, FactorContext source) {
        source.getAttributes().forEach((key, value) -> {
            if (!isSystemAttribute(key)) {
                target.setAttribute(key, value);
            }
        });

        target.setRetryCount(Math.max(target.getRetryCount(), source.getRetryCount()));
        if (source.getLastError() != null) {
            target.setLastError(source.getLastError());
        }
    }

    private void syncFactorContextFromStateMachine(FactorContext target, FactorContext source) {
        target.changeState(source.getCurrentState());
        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setCurrentFactorOptions(source.getCurrentFactorOptions());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }
    }

    private boolean isSystemAttribute(String key) {
        return key.startsWith("_") ||
                "currentState".equals(key) ||
                "version".equals(key) ||
                "lastUpdated".equals(key) ||
                "stateHash".equals(key);
    }

    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context, HttpServletRequest request) {
        Map<String, Object> headers = new HashMap<>();

        // 일반 헤더들
        headers.put("sessionId", context.getMfaSessionId());
        headers.put("username", context.getUsername());
        headers.put("eventTime", System.currentTimeMillis());
        headers.put("version", context.getVersion());
        headers.put("stateHash", context.calculateStateHash());

        // null 체크가 필요한 헤더들
        if (context.getPrimaryAuthentication() != null) {
            headers.put("authentication", context.getPrimaryAuthentication());
        }

        if (request != null) {
            headers.put("request", request);
        }

        Object selectedFactor = request.getAttribute("selectedFactor");
        if (selectedFactor != null) {
            headers.put("selectedFactor", selectedFactor.toString());
        }

        return MessageBuilder
                .withPayload(event)
                .copyHeaders(headers)
                .build();
    }

    // === Circuit Breaker 관련 메서드들 ===

    private ExecutorService getSessionExecutor(String sessionId) {
        return sessionExecutors.computeIfAbsent(sessionId, k -> {
            ThreadFactory threadFactory = r -> {
                Thread thread = new Thread(r, "Optimized-MFA-Session-" + sessionId);
                thread.setDaemon(true);
                return thread;
            };
            return Executors.newSingleThreadExecutor(threadFactory);
        });
    }

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
        successCount.incrementAndGet();
        if (circuitState.get() == CircuitState.HALF_OPEN) {
            circuitState.set(CircuitState.CLOSED);
            failureCount.set(0);
            log.info("Circuit breaker closed after successful operation (success count: {})", successCount.get());
        }
    }

    private void onFailure() {
        lastFailureTime = System.currentTimeMillis();
        int count = failureCount.updateAndGet(c -> c + 1);

        if (count >= failureThreshold) {
            circuitState.set(CircuitState.OPEN);
            log.error("Circuit breaker opened after {} failures (success count: {})", count, successCount.get());
        }
    }

    /**
     * 개선: 상태 및 메트릭 정보 제공
     */
    public Map<String, Object> getHealthMetrics() {
        return Map.of(
                "circuitState", circuitState.get().name(),
                "activeOperations", activeOperations.get(),
                "successCount", successCount.get(),
                "failureCount", failureCount.get(),
                "activeSessions", sessionExecutors.size(),
                "lastFailureTime", lastFailureTime
        );
    }

    public void shutdown() {
        log.info("Shutting down optimized MFA State Machine Service");

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
        log.info("Shutdown completed successfully");
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