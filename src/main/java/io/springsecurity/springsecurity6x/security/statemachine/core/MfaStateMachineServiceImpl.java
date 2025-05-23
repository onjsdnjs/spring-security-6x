package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * MFA State Machine 서비스 구현체
 * 상태 머신의 생명주기 관리 및 이벤트 처리를 담당
 */
@Slf4j
@Service
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final MfaStateMachineFactory stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final FactorContextStateAdapter factorContextAdapter;
    private final ContextPersistence contextPersistence;
    private final MfaEventPublisher eventPublisher;

    // 활성 상태 머신 캐시 (TTL 적용)
    private final Map<String, CachedStateMachine> activeMachines = new ConcurrentHashMap<>();

    // TTL 정리를 위한 스케줄러
    private final ScheduledExecutorService cleanupScheduler = Executors.newSingleThreadScheduledExecutor();

    // 기본 TTL (분)
    private static final int DEFAULT_TTL_MINUTES = 30;

    // 내부 클래스: 캐시된 상태 머신
    private static class CachedStateMachine {
        final StateMachine<MfaState, MfaEvent> stateMachine;
        final LocalDateTime lastAccessTime;

        CachedStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
            this.stateMachine = stateMachine;
            this.lastAccessTime = LocalDateTime.now();
        }

        boolean isExpired(int ttlMinutes) {
            return Duration.between(lastAccessTime, LocalDateTime.now()).toMinutes() > ttlMinutes;
        }
    }

    // 생성자에서 정리 스케줄러 시작
    public MfaStateMachineServiceImpl(MfaStateMachineFactory stateMachineFactory,
                                      StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
                                      FactorContextStateAdapter factorContextAdapter,
                                      ContextPersistence contextPersistence,
                                      MfaEventPublisher eventPublisher) {
        this.stateMachineFactory = stateMachineFactory;
        this.stateMachinePersister = stateMachinePersister;
        this.factorContextAdapter = factorContextAdapter;
        this.contextPersistence = contextPersistence;
        this.eventPublisher = eventPublisher;

        // 5분마다 만료된 상태 머신 정리
        cleanupScheduler.scheduleAtFixedRate(this::cleanupExpiredMachines, 5, 5, TimeUnit.MINUTES);
    }

    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing state machine for session: {}", sessionId);

        try {
            // 기존 상태 머신이 있는지 확인
            StateMachine<MfaState, MfaEvent> existingMachine = getActiveStateMachine(sessionId);
            if (existingMachine != null && isStateMachineValid(existingMachine)) {
                log.warn("State machine already exists for session: {}", sessionId);
                return;
            }

            // 새 상태 머신 생성
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.createStateMachine(sessionId);

            // FactorContext를 상태 머신에 동기화
            Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
            stateMachine.getExtendedState().getVariables().putAll(variables);

            // 활성 머신 목록에 추가
            activeMachines.put(sessionId, new CachedStateMachine(stateMachine));

            // 상태 머신 영속화
            persistStateMachine(stateMachine, sessionId);

            // FactorContext 영속화
            contextPersistence.saveContext(context, request);

            log.info("State machine initialized successfully for session: {}", sessionId);

        } catch (Exception e) {
            log.error("Failed to initialize state machine for session: {}", sessionId, e);
            throw new RuntimeException("Failed to initialize state machine", e);
        }
    }

    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Sending event {} for session: {}", event, sessionId);

        try {
            // 상태 머신 획득
            StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(sessionId, context);

            // FactorContext를 상태 머신에 동기화
            Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
            stateMachine.getExtendedState().getVariables().putAll(variables);

            // 메시지 생성 (헤더에 추가 정보 포함)
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
                // 상태 머신에서 FactorContext 업데이트
                factorContextAdapter.updateFactorContext(stateMachine, context);

                // 영속화
                persistStateMachine(stateMachine, sessionId);
                contextPersistence.saveContext(context, request);

                // 이벤트 발행
                eventPublisher.publishStateChange(sessionId, stateMachine.getState().getId(), event);

                log.info("Event {} accepted and processed for session: {}", event, sessionId);
            } else {
                log.warn("Event {} not accepted for session: {} in state: {}",
                        event, sessionId, stateMachine.getState().getId());
            }

            return accepted;

        } catch (Exception e) {
            log.error("Failed to send event {} for session: {}", event, sessionId, e);
            throw new RuntimeException("Failed to send event", e);
        }
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        try {
            StateMachine<MfaState, MfaEvent> stateMachine = getActiveStateMachine(sessionId);
            if (stateMachine != null && stateMachine.getState() != null) {
                return stateMachine.getState().getId();
            }

            // 활성 머신이 없으면 영속화된 상태 확인
            stateMachine = stateMachineFactory.restoreStateMachine(sessionId);
            if (stateMachine != null && stateMachine.getState() != null) {
                activeMachines.put(sessionId, new CachedStateMachine(stateMachine));
                return stateMachine.getState().getId();
            }

            return MfaState.NONE;

        } catch (Exception e) {
            log.error("Failed to get current state for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing state machine for session: {}", sessionId);

        try {
            // 활성 머신 목록에서 제거
            CachedStateMachine cached = activeMachines.remove(sessionId);
            if (cached != null) {
                // 최종 상태 영속화
                persistStateMachine(cached.stateMachine, sessionId);

                // 팩토리를 통해 추가 정리
                stateMachineFactory.releaseStateMachine(sessionId);
            }

            log.info("State machine released for session: {}", sessionId);

        } catch (Exception e) {
            log.error("Error releasing state machine for session: {}", sessionId, e);
        }
    }

    /**
     * 상태 머신 획득 (캐시 또는 복원)
     */
    private StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId,
                                                                 FactorContext context) {
        // 캐시에서 확인
        CachedStateMachine cached = activeMachines.get(sessionId);
        if (cached != null && isStateMachineValid(cached.stateMachine)) {
            // 접근 시간 갱신
            activeMachines.put(sessionId, new CachedStateMachine(cached.stateMachine));
            return cached.stateMachine;
        }

        // 영속화된 상태 복원 시도
        try {
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.restoreStateMachine(sessionId);
            if (stateMachine != null && isStateMachineValid(stateMachine)) {
                // FactorContext 정보로 변수 업데이트
                if (context != null) {
                    Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
                    stateMachine.getExtendedState().getVariables().putAll(variables);
                }

                activeMachines.put(sessionId, new CachedStateMachine(stateMachine));
                return stateMachine;
            }
        } catch (Exception e) {
            log.warn("Failed to restore state machine for session: {}, creating new one", sessionId);
        }

        // 새로 생성
        StateMachine<MfaState, MfaEvent> newStateMachine = stateMachineFactory.createStateMachine(sessionId);
        if (context != null) {
            Map<Object, Object> variables = factorContextAdapter.toStateMachineVariables(context);
            newStateMachine.getExtendedState().getVariables().putAll(variables);
        }

        activeMachines.put(sessionId, new CachedStateMachine(newStateMachine));
        return newStateMachine;
    }

    /**
     * 상태 머신 영속화
     */
    private void persistStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String sessionId) {
        try {
            stateMachinePersister.persist(stateMachine, sessionId);
        } catch (Exception e) {
            log.error("Failed to persist state machine for session: {}", sessionId, e);
        }
    }

    /**
     * 상태 머신 유효성 검사
     */
    private boolean isStateMachineValid(StateMachine<MfaState, MfaEvent> stateMachine) {
        return stateMachine != null &&
                !stateMachine.hasStateMachineError() &&
                stateMachine.getState() != null;
    }

    /**
     * 활성 상태 머신 가져오기
     */
    private StateMachine<MfaState, MfaEvent> getActiveStateMachine(String sessionId) {
        CachedStateMachine cached = activeMachines.get(sessionId);
        return cached != null ? cached.stateMachine : null;
    }

    /**
     * 만료된 상태 머신 정리
     */
    private void cleanupExpiredMachines() {
        log.debug("Starting cleanup of expired state machines");

        int cleaned = 0;
        for (Map.Entry<String, CachedStateMachine> entry : activeMachines.entrySet()) {
            if (entry.getValue().isExpired(DEFAULT_TTL_MINUTES)) {
                String sessionId = entry.getKey();
                releaseStateMachine(sessionId);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            log.info("Cleaned up {} expired state machines", cleaned);
        }
    }

    // Shutdown hook
    public void shutdown() {
        cleanupScheduler.shutdown();
        try {
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupScheduler.shutdownNow();
        }
    }
}