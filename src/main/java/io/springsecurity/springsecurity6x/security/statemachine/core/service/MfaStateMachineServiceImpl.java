package io.springsecurity.springsecurity6x.security.statemachine.core.service;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.support.StateContextHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration; // Duration import
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final ObjectProvider<StateMachine<MfaState, MfaEvent>> stateMachineProvider;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final RedissonClient redissonClient;

    private static final long LOCK_WAIT_TIME_SECONDS = 10;
    private static final long LOCK_LEASE_TIME_SECONDS = 30;
    private static final MfaState FALLBACK_INITIAL_MFA_STATE = MfaState.NONE;
    private static final long EVENT_PROCESSING_TIMEOUT_SECONDS = 5; // 이벤트 처리 타임아웃

    private String getLockKey(String sessionId) {
        return "mfa_lock:session:" + sessionId;
    }

    private StateMachine<MfaState, MfaEvent> getAndPrepareStateMachine(String machineId) {
        StateMachine<MfaState, MfaEvent> stateMachine = stateMachineProvider.getObject();
        try {
            stateMachinePersister.restore(stateMachine, machineId);
            log.debug("[MFA SM Service] [{}] 풀에서 가져온 SM에 상태 복원 완료. 현재 상태: {}", machineId, stateMachine.getState() != null ? stateMachine.getState().getId() : "N/A");
            // restore 후 SM은 로드된 상태에 있게 되며, 일반적으로 별도의 start() 호출 없이 이벤트 처리 가능.
            // 만약 restore 후 SM이 '중단' 상태이고 수동 시작이 필요하다면,
            // 여기서 stateMachine.getState() != null && !stateMachine.getStateMachineAccessor().isComplete() 등을 확인 후 시작.
            // 지금은 restore가 SM을 사용 가능한 상태로 만든다고 가정.
        } catch (Exception e) {
            log.warn("[MFA SM Service] [{}] 상태 머신 복원 실패 또는 새 세션. SM은 '깨끗한' 상태. 오류: {}", machineId, e.getMessage());
            resetStateMachine(stateMachine, machineId, FALLBACK_INITIAL_MFA_STATE, null);
            // resetStateMachine 내부에서 startReactively().block() 호출
            log.debug("[MFA SM Service] [{}] 새/리셋된 SM 시작 완료 (getAndPrepareStateMachine).", machineId);
        }
        return stateMachine;
    }

    private void resetStateMachine(StateMachine<MfaState, MfaEvent> stateMachine, String machineId, MfaState targetState, FactorContext factorContext) {
        // 상태 머신이 어떤 상태에 있거나 시작된 것으로 간주되면 중지
        if (stateMachine.getState() != null) {
            stateMachine.stopReactively().block();
            log.debug("[MFA SM Service] [{}] SM 리셋 전 중지 완료.", machineId);
        }

        ExtendedState extendedState = stateMachine.getExtendedState();
        extendedState.getVariables().clear();
        if (factorContext != null) {
            StateContextHelper.setFactorContext(extendedState, factorContext);
            log.debug("[MFA SM Service] [{}] 리셋 중 FactorContext (버전:{})를 ExtendedState에 설정.", machineId, factorContext.getVersion());
        }

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, extendedState, null, machineId
        );
        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());
        log.debug("[MFA SM Service] [{}] SM 초기 상태({})로 리셋 완료.", machineId, targetState);

        // 리셋 후에는 항상 SM을 시작
        stateMachine.startReactively().block();
        log.debug("[MFA SM Service] [{}] 리셋된 SM 시작 완료.", machineId);
    }


    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] SM 초기화 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);

            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] SM 초기화 위한 락 획득 실패.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for State Machine initialization: " + sessionId);
            }
            log.debug("[MFA SM Service] [{}] SM 초기화 위한 락 획득.", sessionId);

            stateMachine = stateMachineProvider.getObject();

            resetStateMachine(stateMachine, sessionId, context.getCurrentState(), context); // 여기서 SM 시작 포함
            log.info("[MFA SM Service] [{}] SM 초기화 및 FactorContext와 동기화 완료. SM 상태: {}, FactorContext 버전: {}",
                    sessionId, stateMachine.getState().getId(), context.getVersion());

            Message<MfaEvent> message = createEventMessage(MfaEvent.PRIMARY_AUTH_SUCCESS, context, request);

            log.debug("[MFA SM Service] [{}] 이벤트 전송 (initialize): {}", sessionId, message.getPayload());
            Boolean accepted = stateMachine.sendEvent(Mono.just(message))
                    .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                    .blockFirst(Duration.ofSeconds(EVENT_PROCESSING_TIMEOUT_SECONDS)); // Duration 타입 인자 사용

            boolean eventAccepted = Boolean.TRUE.equals(accepted); // Null-safe check

            MfaState smCurrentStateAfterEvent = stateMachine.getState().getId();
            FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

            if (!eventAccepted) {
                log.warn("[MFA SM Service] [{}] SM 초기화 중 PRIMARY_AUTH_SUCCESS 이벤트가 수락되지 않음. 현재 SM 상태: {}", sessionId, smCurrentStateAfterEvent);
            } else {
                log.info("[MFA SM Service] [{}] 이벤트 {} 처리 후 상태: {}", sessionId, message.getPayload(), smCurrentStateAfterEvent);
            }

            if (contextFromSmAfterEvent != null) {
                context.changeState(smCurrentStateAfterEvent);
                context.setVersion(contextFromSmAfterEvent.getVersion());
                context.getAttributes().clear();
                context.getAttributes().putAll(contextFromSmAfterEvent.getAttributes());
            } else {
                log.warn("[MFA SM Service] [{}] 이벤트 처리 후 SM에서 FactorContext를 찾을 수 없음. 외부 context 상태만 SM 상태로 업데이트.", sessionId);
                context.changeState(smCurrentStateAfterEvent);
            }

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            stateMachinePersister.persist(stateMachine, sessionId);
            log.debug("[MFA SM Service] [{}] SM 영속화 완료 (initialize). 최종 FactorContext 버전: {}", sessionId, context.getVersion());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] SM 초기화 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("State Machine initialization interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] SM 초기화 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] SM 초기화 락 해제.", sessionId);
            }
        }
    }

    @Override
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득 시도.", sessionId, event);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득 실패.", sessionId, event);
                return false;
            }
            log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 위한 락 획득.", sessionId, event);

            stateMachine = getAndPrepareStateMachine(sessionId);

            if (stateMachine.getState() == null || stateMachine.getState().getId() == null) {
                log.warn("[MFA SM Service] [{}] SM 복원 후 상태가 null. 외부 FactorContext 상태({})로 SM 강제 리셋 및 시작.", sessionId, context.getCurrentState());
                resetStateMachine(stateMachine, sessionId, context.getCurrentState(), context);
            } else {
                StateContextHelper.setFactorContext(stateMachine, context);
                log.debug("[MFA SM Service] [{}] SM 정상 복원됨. 외부 FactorContext(버전:{}) SM에 설정.", sessionId, context.getVersion());
            }

            context.incrementVersion();
            StateContextHelper.setFactorContext(stateMachine, context);

            Message<MfaEvent> message = createEventMessage(event, context, request);
            log.debug("[MFA SM Service] [{}] 이벤트 전송: {}", sessionId, message.getPayload());
            Boolean accepted = stateMachine.sendEvent(Mono.just(message))
                    .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                    .blockFirst(Duration.ofSeconds(EVENT_PROCESSING_TIMEOUT_SECONDS));

            boolean eventAccepted = Boolean.TRUE.equals(accepted);

            MfaState smCurrentStateAfterEvent = stateMachine.getState().getId();
            FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);

            if (eventAccepted) {
                log.info("[MFA SM Service] [{}] 이벤트 {} 처리 후 SM 상태: {}", sessionId, message.getPayload(), smCurrentStateAfterEvent);
            } else {
                log.warn("[MFA SM Service] [{}] 이벤트 ({})가 현재 SM 상태 ({})에서 수락되지 않음.", sessionId, event, smCurrentStateAfterEvent);
            }

            if (contextFromSmAfterEvent != null) {
                context.changeState(smCurrentStateAfterEvent);
                context.setVersion(contextFromSmAfterEvent.getVersion());
                context.getAttributes().clear();
                context.getAttributes().putAll(contextFromSmAfterEvent.getAttributes());
                // ... 기타 필드 동기화 ...
            } else {
                log.error("[MFA SM Service] [{}] 이벤트 처리 후 SM에서 FactorContext를 찾을 수 없음! 외부 context 상태만 SM 상태로 업데이트.", sessionId);
                context.changeState(smCurrentStateAfterEvent);
            }

            StateContextHelper.setFactorContext(stateMachine, context);

            stateMachinePersister.persist(stateMachine, sessionId);
            log.debug("[MFA SM Service] [{}] 상태 머신 영속화 완료. 최종 FactorContext 버전: {}", sessionId, context.getVersion());

            return eventAccepted;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] 이벤트 ({}) 처리 중 인터럽트 발생.", sessionId, event, e);
            throw new MfaStateMachineException("MFA event processing interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] 이벤트 ({}) 처리 중 오류 발생.", sessionId, event, e);
            throw new MfaStateMachineException("Error during MFA event processing for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 이벤트 ({}) 처리 락 해제.", sessionId, event);
            }
        }
    }

    @Override
    public FactorContext getFactorContext(String sessionId) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;
        try {
            log.debug("[MFA SM Service] [{}] FactorContext 조회 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS / 2, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] FactorContext 조회 위한 락 획득 실패. null 반환.", sessionId);
                return null;
            }
            log.debug("[MFA SM Service] [{}] FactorContext 조회 위한 락 획득.", sessionId);

            stateMachine = stateMachineProvider.getObject();
            FactorContext factorContext = null;
            try {
                stateMachinePersister.restore(stateMachine, sessionId);
                log.debug("[MFA SM Service] [{}] FactorContext 조회 위한 SM 복원 성공. SM 상태: {}", sessionId, stateMachine.getState() != null ? stateMachine.getState().getId() : "N/A");
                factorContext = StateContextHelper.getFactorContext(stateMachine);
            } catch (Exception e) {
                log.warn("[MFA SM Service] [{}] FactorContext 조회 위한 SM 복원 실패. 오류: {}", sessionId, e.getMessage());
                return null;
            }

            if (factorContext == null) {
                log.info("[MFA SM Service] [{}] SM 복원 후 FactorContext 없음.", sessionId);
            } else {
                log.debug("[MFA SM Service] [{}] FactorContext 조회 성공. 버전: {}", sessionId, factorContext.getVersion());
            }
            return factorContext;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] FactorContext 조회 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("Get FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] FactorContext 조회 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during getFactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] FactorContext 조회 락 해제.", sessionId);
            }
        }
    }

    @Override
    public void saveFactorContext(FactorContext context) {
        String sessionId = context.getMfaSessionId();
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] FactorContext 저장 위한 락 획득 시도.", sessionId);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] FactorContext 저장 위한 락 획득 실패.", sessionId);
                throw new MfaStateMachineException("Failed to acquire lock for saving FactorContext: " + sessionId);
            }
            log.debug("[MFA SM Service] [{}] FactorContext 저장 위한 락 획득.", sessionId);

            stateMachine = getAndPrepareStateMachine(sessionId);

            context.incrementVersion();
            resetStateMachine(stateMachine, sessionId, context.getCurrentState(), context); // SM 상태와 ExtendedState를 context와 동기화하고 시작
            log.debug("[MFA SM Service] [{}] 외부 FactorContext (버전:{}) SM에 동기화 후 영속화 시도.", sessionId, context.getVersion());

            stateMachinePersister.persist(stateMachine, sessionId);
            log.info("[MFA SM Service] [{}] FactorContext 명시적 저장 및 SM 영속화 완료. 버전: {}", sessionId, context.getVersion());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] FactorContext 저장 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("Saving FactorContext interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] FactorContext 저장 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during saving FactorContext for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] FactorContext 저장 락 해제.", sessionId);
            }
        }
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        FactorContext context = getFactorContext(sessionId);
        if (context != null) {
            return context.getCurrentState();
        }
        log.warn("[MFA SM Service] [{}] 현재 상태 조회 실패: FactorContext를 찾을 수 없음. NONE 반환.", sessionId);
        return MfaState.NONE;
    }

    @Override
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        String lockKey = getLockKey(sessionId);
        RLock lock = redissonClient.getLock(lockKey);
        boolean lockAcquired = false;
        StateMachine<MfaState, MfaEvent> stateMachine = null;

        try {
            log.debug("[MFA SM Service] [{}] 상태만 업데이트 위한 락 획득 시도: -> {}", sessionId, newState);
            lockAcquired = lock.tryLock(LOCK_WAIT_TIME_SECONDS, LOCK_LEASE_TIME_SECONDS, TimeUnit.SECONDS);
            if (!lockAcquired) {
                log.warn("[MFA SM Service] [{}] 상태만 업데이트 위한 락 획득 실패.", sessionId);
                return false;
            }
            log.debug("[MFA SM Service] [{}] 상태만 업데이트 위한 락 획득.", sessionId);

            stateMachine = getAndPrepareStateMachine(sessionId);
            FactorContext factorContext = StateContextHelper.getFactorContext(stateMachine);

            if (factorContext == null) {
                log.warn("[MFA SM Service] [{}] 상태만 업데이트 실패: FactorContext 없음. 새 FactorContext 생성 시도.", sessionId);
                // 이 경우, primaryAuthentication 등의 필수 정보가 없으므로 완전한 FactorContext 생성 불가.
                // 상태만 업데이트하는 것이므로, 기존 FactorContext가 반드시 있어야 함.
                // 여기서는 FactorContext가 없으면 업데이트 실패로 간주.
                return false;
            }

            factorContext.changeState(newState);
            // factorContext.incrementVersion(); // changeState에서 버전업 처리 가정

            resetStateMachine(stateMachine, sessionId, newState, factorContext); // SM 상태와 ExtendedState를 factorContext와 동기화하고 시작

            stateMachinePersister.persist(stateMachine, sessionId);
            log.info("[MFA SM Service] [{}] 상태만 업데이트 완료: {}. FactorContext 버전: {}", sessionId, newState, factorContext.getVersion());
            return true;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[MFA SM Service] [{}] 상태만 업데이트 중 인터럽트 발생.", sessionId, e);
            throw new MfaStateMachineException("State-only update interrupted: " + sessionId, e);
        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] 상태만 업데이트 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during state-only update for " + sessionId + ": " + e.getMessage(), e);
        } finally {
            if (lockAcquired && lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("[MFA SM Service] [{}] 상태만 업데이트 락 해제.", sessionId);
            }
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.info("[MFA SM Service] [{}] 세션에 대한 상태 머신 컨텍스트 정리 요청.", sessionId);
        // Redis에서 "spring:statemachine:context:" + sessionId 키를 직접 삭제하는 로직 필요 시 추가
    }

    private Message<MfaEvent> createEventMessage(MfaEvent event, FactorContext context, HttpServletRequest request) {
        Map<String, Object> headers = new HashMap<>();
        if (context != null) {
            headers.put("sessionId", context.getMfaSessionId());
            if (context.getPrimaryAuthentication() != null && context.getPrimaryAuthentication().getName() != null) {
                headers.put("username", context.getPrimaryAuthentication().getName());
            }
            headers.put("version", context.getVersion());
            headers.put("stateHash", context.calculateStateHash());
            if (context.getPrimaryAuthentication() != null) {
                headers.put("authentication", context.getPrimaryAuthentication());
            }
        }

        if (request != null) {
            Object selectedFactor = request.getAttribute("selectedFactor");
            if (selectedFactor != null) {
                headers.put("selectedFactor", selectedFactor.toString());
            }
        }
        return MessageBuilder.withPayload(event).copyHeaders(headers).build();
    }

    private boolean isTerminalState(MfaState state) {
        if (state == null) return false;
        return state.isTerminal();
    }

    public static class MfaStateMachineException extends RuntimeException {
        public MfaStateMachineException(String message) { super(message); }
        public MfaStateMachineException(String message, Throwable cause) { super(message, cause); }
    }
}