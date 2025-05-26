package io.springsecurity.springsecurity6x.security.core.mfa.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.config.redis.RedisDistributedLockService;
import io.springsecurity.springsecurity6x.security.statemachine.config.StateMachineProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.persist.ResilientRedisStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.lang.Nullable;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 통합 ContextPersistence 구현
 * - 설정에 따라 HTTP Session 또는 Redis 사용
 * - State Machine과의 원자적 저장 지원
 */
@Slf4j
public class UnifiedContextPersistence implements ContextPersistence {

    private final ContextPersistence delegate;
    private final StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist;
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisDistributedLockService distributedLockService;
    private final boolean atomicSaveEnabled;

    private static final String STATE_MACHINE_PREFIX = "mfa:statemachine:";

    public UnifiedContextPersistence(
            @Value("${security.mfa.context-persistence.type:session}") String persistenceType,
            @Value("${security.mfa.context-persistence.atomic-save:true}") boolean atomicSaveEnabled,
            HttpSessionContextPersistence sessionPersistence,
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService distributedLockService,
            ObjectMapper objectMapper,
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist,
            StateMachineProperties properties) {

        this.atomicSaveEnabled = atomicSaveEnabled;
        this.redisTemplate = redisTemplate;
        this.distributedLockService = distributedLockService;
        this.stateMachinePersist = stateMachinePersist;

        // 설정에 따라 구현체 선택
        if ("redis".equalsIgnoreCase(persistenceType)) {
            log.info("Using Redis-based FactorContext persistence");
            this.delegate = new RedisContextPersistence(redisTemplate, distributedLockService, objectMapper);
        } else {
            log.info("Using HTTP Session-based FactorContext persistence");
            this.delegate = sessionPersistence;
        }
    }

    @Override
    @Nullable
    public FactorContext contextLoad(HttpServletRequest request) {
        return delegate.contextLoad(request);
    }

    @Override
    @Nullable
    public FactorContext loadContext(String sessionId, HttpServletRequest request) {
        return delegate.loadContext(sessionId, request);
    }

    @Override
    public void saveContext(@Nullable FactorContext ctx, HttpServletRequest request) {
        if (ctx == null) {
            delegate.saveContext(null, request);
            return;
        }

        // 원자적 저장이 활성화되고 Redis를 사용하는 경우
        if (atomicSaveEnabled && delegate instanceof RedisContextPersistence && stateMachinePersist instanceof ResilientRedisStateMachinePersist) {
            saveContextAtomically(ctx, request);
        } else {
            // 일반 저장
            delegate.saveContext(ctx, request);
        }
    }

    @Override
    public void deleteContext(HttpServletRequest request) {
        delegate.deleteContext(request);
    }

    /**
     * FactorContext와 State Machine 상태를 원자적으로 저장
     */
    private void saveContextAtomically(FactorContext ctx, HttpServletRequest request) {
        String mfaSessionId = ctx.getMfaSessionId();

        try {
            // 분산 락 획득
            distributedLockService.executeWithLock(
                    "atomic:save:" + mfaSessionId,
                    Duration.ofSeconds(5),
                    () -> {
                        // Redis 트랜잭션으로 원자적 저장
                        List<Object> results = redisTemplate.execute(new SessionCallback<List<Object>>() {
                            @Override
                            public List<Object> execute(org.springframework.data.redis.core.RedisOperations operations) {
                                operations.multi();

                                try {
                                    // 1. FactorContext 저장 (delegate를 통해)
                                    delegate.saveContext(ctx, request);

                                    // 2. State Machine 상태도 동일 트랜잭션에서 저장
                                    if (shouldSaveStateMachine(ctx)) {
                                        StateMachineContext<MfaState, MfaEvent> smContext = createStateMachineContext(ctx);

                                        // State Machine persist를 Redis 트랜잭션에 포함
                                        String smKey = STATE_MACHINE_PREFIX + mfaSessionId;
                                        String serialized = serializeStateMachineContext(smContext);
                                        operations.opsForValue().set(smKey, serialized, 30, TimeUnit.MINUTES);
                                    }

                                    // 3. 버전 정보 저장
                                    String versionKey = "mfa:version:" + mfaSessionId;
                                    operations.opsForValue().set(versionKey, ctx.getVersion(), 30, TimeUnit.MINUTES);

                                } catch (Exception e) {
                                    log.error("Error during atomic save transaction", e);
                                    operations.discard();
                                    return null;
                                }

                                return operations.exec();
                            }
                        });

                        if (results != null && !results.isEmpty()) {
                            log.debug("Atomically saved FactorContext and State Machine for session: {}", mfaSessionId);
                        } else {
                            throw new RuntimeException("Atomic save transaction failed");
                        }

                        return null;
                    }
            );
        } catch (Exception e) {
            log.error("Failed to save atomically, falling back to normal save", e);
            // Fallback: 일반 저장
            delegate.saveContext(ctx, request);
        }
    }

    /**
     * State Machine 저장이 필요한지 확인
     */
    private boolean shouldSaveStateMachine(FactorContext ctx) {
        // 상태가 변경되었거나 중요한 전환점인 경우
        return ctx.getCurrentState() != MfaState.NONE &&
                !ctx.getCurrentState().isTerminal();
    }

    /**
     * FactorContext로부터 StateMachineContext 생성
     */
    private StateMachineContext<MfaState, MfaEvent> createStateMachineContext(FactorContext ctx) {
        // 간단한 구현 - 실제로는 StateContextHelper를 활용
        return new StateMachineContext<MfaState, MfaEvent>() {
            @Override
            public MfaState getState() {
                return ctx.getCurrentState();
            }

            @Override
            public MfaEvent getEvent() {
                return null; // 현재 이벤트는 저장하지 않음
            }

            @Override
            public Map<MfaState, MfaState> getHistoryStates() {
                return Map.of();
            }

            @Override
            public Map<String, Object> getEventHeaders() {
                return Map.of(
                        "mfaSessionId", ctx.getMfaSessionId(),
                        "username", ctx.getUsername(),
                        "version", ctx.getVersion()
                );
            }

            @Override
            public org.springframework.statemachine.ExtendedState getExtendedState() {
                // FactorContext의 중요 정보를 ExtendedState로 변환
                return null; // 실제 구현 필요
            }

            @Override
            public String getId() {
                return "";
            }

            @Override
            public List<StateMachineContext<MfaState, MfaEvent>> getChilds() {
                return List.of();
            }

            @Override
            public List<String> getChildReferences() {
                return List.of();
            }
        };
    }

    /**
     * StateMachineContext 직렬화 (간단한 구현)
     */
    private String serializeStateMachineContext(StateMachineContext<MfaState, MfaEvent> context) throws Exception {
        // 실제로는 ResilientRedisStateMachinePersist의 직렬화 로직 사용
        return context.getState().name();
    }
}