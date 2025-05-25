package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * 확장 가능한 MFA State Machine 서비스 구현
 */
@Slf4j
@Service
public class ScalableMfaStateMachineService implements MfaStateMachineService {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final FactorContextStateAdapter factorContextAdapter;
    private final ContextPersistence contextPersistence;
    private final MfaEventPublisher eventPublisher;
    private final RedisDistributedLockService lockService;
    private final RedisTemplate<String, String> redisTemplate;

    // 캐시
    private final Map<String, CachedStateMachine> stateMachineCache = new ConcurrentHashMap<>();

    // 설정값
    @Value("${security.statemachine.cache-ttl-minutes:5}")
    private int cacheTtlMinutes;

    @Value("${security.statemachine.lock-timeout-seconds:10}")
    private int lockTimeoutSeconds;

    @Value("${security.statemachine.max-retry-attempts:3}")
    private int maxRetryAttempts;

    // Executor for async operations
    private final ExecutorService asyncExecutor = Executors.newCachedThreadPool();

    public ScalableMfaStateMachineService(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            FactorContextStateAdapter factorContextAdapter,
            ContextPersistence contextPersistence,
            @Qualifier("mfaEventPublisher") MfaEventPublisher eventPublisher,
            RedisDistributedLockService lockService,
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, String> redisTemplate) {

        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.factorContextAdapter = factorContextAdapter;
        this.contextPersistence = contextPersistence;
        this.eventPublisher = eventPublisher;
        this.lockService = lockService;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing state machine for session: {}", sessionId);

        try {
            lockService.executeWithLock(
                    "sm:init:" + sessionId,
                    Duration.ofSeconds(lockTimeoutSeconds),
                    () -> {
                        // 중복 초기화 방지
                        if (isStateMachineExists(sessionId)) {
                            log.warn("State machine already exists for session: {}", sessionId);
                            return null;
                        }

                        // State Machine 생성
                        StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.getStateMachine(sessionId);

                        // 초기 컨텍스트 설정
                        Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
                        stateMachine.getExtendedState().getVariables().putAll(variables);
                        stateMachine.getExtendedState().getVariables().put("createdAt", System.currentTimeMillis());

                        // State Machine 시작
                        stateMachine.start();

                        // 영속화
                        persistStateMachine(sessionId, stateMachine);
                        contextPersistence.saveContext(context, request);

                        // 캐시에 추가
                        cacheStateMachine(sessionId, stateMachine);

                        // 초기화 이벤트 발행
                        publishEvent(sessionId, MfaState.NONE, MfaState.START_MFA, MfaEvent.PRIMARY_AUTH_SUCCESS);

                        log.info("State machine initialized successfully for session: {}", sessionId);
                        return null;
                    }
            );
        } catch (Exception e) {
            log.error("Failed to initialize state machine for session: {}", sessionId, e);
            throw new StateMachineException("Failed to initialize state machine", e);
        }
    }

    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Processing event {} for session: {}", event, sessionId);

        // 재시도 로직
        for (int attempt = 1; attempt <= maxRetryAttempts; attempt++) {
            try {
                return lockService.executeWithLock(
                        "sm:event:" + sessionId,
                        Duration.ofSeconds(lockTimeoutSeconds),
                        () -> processEvent(sessionId, event, context, request)
                );
            } catch (RedisDistributedLockService.LockAcquisitionException e) {
                if (attempt == maxRetryAttempts) {
                    throw new ConcurrentModificationException("Failed to acquire lock after " + attempt + " attempts");
                }
                log.warn("Lock acquisition failed for session: {}, retrying... (attempt {})", sessionId, attempt);
                sleepWithBackoff(attempt);
            } catch (Exception e) {
                log.error("Error processing event for session: {}", sessionId, e);
                throw new StateMachineException("Event processing failed", e);
            }
        }

        return false;
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        try {
            // 1. 캐시 확인
            CachedStateMachine cached = stateMachineCache.get(sessionId);
            if (cached != null && !cached.isExpired(cacheTtlMinutes)) {
                return cached.stateMachine.getState().getId();
            }

            // 2. Redis에서 복원
            StateMachine<MfaState, MfaEvent> stateMachine = restoreStateMachine(sessionId);
            if (stateMachine != null && stateMachine.getState() != null) {
                cacheStateMachine(sessionId, stateMachine);
                return stateMachine.getState().getId();
            }

            // 3. 기본값
            return MfaState.NONE;

        } catch (Exception e) {
            log.error("Failed to get current state for session: {}", sessionId, e);
            return getStateFromContext(sessionId);
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing state machine for session: {}", sessionId);

        // 비동기 처리
        CompletableFuture.runAsync(() -> {
            try {
                // 캐시 제거
                CachedStateMachine cached = stateMachineCache.remove(sessionId);

                if (cached != null) {
                    // 최종 상태 영속화
                    persistStateMachine(sessionId, cached.stateMachine);
                }

                // Redis 정리
                cleanupRedisData(sessionId);

                log.info("State machine released for session: {}", sessionId);

            } catch (Exception e) {
                log.error("Error releasing state machine for session: {}", sessionId, e);
            }
        }, asyncExecutor);
    }

    /**
     * 이벤트 처리 핵심 로직
     */
    private boolean processEvent(String sessionId, MfaEvent event,
                                 FactorContext context, HttpServletRequest request) throws Exception {

        // State Machine 조회 또는 복원
        StateMachine<MfaState, MfaEvent> stateMachine = getOrRestoreStateMachine(sessionId);

        // 현재 상태 확인
        MfaState currentState = stateMachine.getState().getId();

        // Context 동기화
        Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
        stateMachine.getExtendedState().getVariables().putAll(variables);

        // 메시지 생성
        Message<MfaEvent> message = MessageBuilder
                .withPayload(event)
                .setHeader("mfaSessionId", sessionId)
                .setHeader("authentication", context.getPrimaryAuthentication())
                .setHeader("request", request)
                .setHeader("timestamp", System.currentTimeMillis())
                .build();

        // 이벤트 전송
        boolean accepted = stateMachine.sendEvent(message);

        if (accepted) {
            MfaState newState = stateMachine.getState().getId();

            // Context 업데이트
            factorContextAdapter.updateFactorContext(stateMachine, context);

            // 영속화
            persistStateMachine(sessionId, stateMachine);
            contextPersistence.saveContext(context, request);

            // 캐시 갱신
            cacheStateMachine(sessionId, stateMachine);

            // 이벤트 발행
            publishEvent(sessionId, currentState, newState, event);

            log.info("Event {} accepted. State transition: {} -> {} for session: {}",
                    event, currentState, newState, sessionId);
        } else {
            log.warn("Event {} rejected in state {} for session: {}",
                    event, currentState, sessionId);
        }

        return accepted;
    }

    /**
     * State Machine 조회 또는 복원
     */
    private StateMachine<MfaState, MfaEvent> getOrRestoreStateMachine(String sessionId) {
        // 1. 캐시 확인
        CachedStateMachine cached = stateMachineCache.get(sessionId);
        if (cached != null && !cached.isExpired(cacheTtlMinutes)) {
            return cached.stateMachine;
        }

        // 2. 복원 시도
        StateMachine<MfaState, MfaEvent> stateMachine = restoreStateMachine(sessionId);
        if (stateMachine != null) {
            cacheStateMachine(sessionId, stateMachine);
            return stateMachine;
        }

        // 3. 새로 생성 (이례적인 경우)
        throw new IllegalStateException("State machine not found for session: " + sessionId);
    }

    /**
     * State Machine 복원
     */
    private StateMachine<MfaState, MfaEvent> restoreStateMachine(String sessionId) {
        try {
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.getStateMachine(sessionId);
            stateMachinePersister.restore(stateMachine, sessionId);

            // 복원 후 시작되지 않은 경우 시작
            if (!stateMachine.isComplete() && stateMachine.getState() == null) {
                stateMachine.start();
            }

            return stateMachine;
        } catch (Exception e) {
            log.error("Failed to restore state machine for session: {}", sessionId, e);
            return null;
        }
    }

    /**
     * State Machine 영속화
     */
    private void persistStateMachine(String sessionId, StateMachine<MfaState, MfaEvent> stateMachine) {
        try {
            stateMachinePersister.persist(stateMachine, sessionId);

            // 메타데이터 저장
            String metaKey = "mfa:meta:" + sessionId;
            redisTemplate.opsForHash().put(metaKey, "lastUpdated", String.valueOf(System.currentTimeMillis()));
            redisTemplate.opsForHash().put(metaKey, "state", stateMachine.getState().getId().name());
            redisTemplate.expire(metaKey, Duration.ofMinutes(30));

        } catch (Exception e) {
            log.error("Failed to persist state machine for session: {}", sessionId, e);
            throw new StateMachineException("Persistence failed", e);
        }
    }

    /**
     * State Machine 존재 여부 확인
     */
    private boolean isStateMachineExists(String sessionId) {
        // 캐시 확인
        if (stateMachineCache.containsKey(sessionId)) {
            return true;
        }

        // Redis 메타데이터 확인
        String metaKey = "mfa:meta:" + sessionId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(metaKey));
    }

    /**
     * State Machine 캐싱
     */
    private void cacheStateMachine(String sessionId, StateMachine<MfaState, MfaEvent> stateMachine) {
        stateMachineCache.put(sessionId, new CachedStateMachine(stateMachine));
    }

    /**
     * 이벤트 발행
     */
    private void publishEvent(String sessionId, MfaState fromState, MfaState toState, MfaEvent event) {
        try {
            eventPublisher.publishStateChange(sessionId, toState, event);
        } catch (Exception e) {
            // 이벤트 발행 실패는 전체 프로세스를 중단시키지 않음
            log.warn("Failed to publish event for session: {}", sessionId, e);
        }
    }

    /**
     * Context에서 상태 조회 (Fallback)
     */
    private MfaState getStateFromContext(String sessionId) {
        try {
            FactorContext context = contextPersistence.loadContext(sessionId, null);
            return context != null ? context.getCurrentState() : MfaState.NONE;
        } catch (Exception e) {
            return MfaState.NONE;
        }
    }

    /**
     * Redis 데이터 정리
     */
    private void cleanupRedisData(String sessionId) {
        try {
            redisTemplate.delete("mfa:meta:" + sessionId);
        } catch (Exception e) {
            log.warn("Failed to cleanup Redis data for session: {}", sessionId, e);
        }
    }

    /**
     * 백오프 대기
     */
    private void sleepWithBackoff(int attempt) {
        try {
            long waitTime = Math.min(100L * (1L << attempt), 1000L);
            Thread.sleep(waitTime);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 캐시된 State Machine
     */
    private static class CachedStateMachine {
        final StateMachine<MfaState, MfaEvent> stateMachine;
        final long timestamp;

        CachedStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
            this.stateMachine = stateMachine;
            this.timestamp = System.currentTimeMillis();
        }

        boolean isExpired(int ttlMinutes) {
            long age = System.currentTimeMillis() - timestamp;
            return age > TimeUnit.MINUTES.toMillis(ttlMinutes);
        }
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

    /**
     * 동시 수정 예외
     */
    public static class ConcurrentModificationException extends RuntimeException {
        public ConcurrentModificationException(String message) {
            super(message);
        }
    }
}