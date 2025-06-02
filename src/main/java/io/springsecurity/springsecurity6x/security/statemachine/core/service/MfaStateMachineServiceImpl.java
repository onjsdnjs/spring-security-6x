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
import org.springframework.aop.framework.Advised;
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

import java.time.Duration;
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
        if (stateMachine.getState() != null) {
            stateMachine.stopReactively().block();
            log.debug("[MFA SM Service] [{}] SM 리셋 전 중지 완료.", machineId);
        }

        // 1. 리셋을 위한 기본 ExtendedState 준비 (내용은 비워져 있을 수 있음)
        //    resetStateMachineReactively는 이 extendedState 객체 자체를 내부적으로 사용할 수도 있고,
        //    아니면 단순히 내부 변수 초기화에만 사용할 수도 있음.
        ExtendedState preparedExtendedStateForReset = stateMachine.getExtendedState(); // 현재 SM의 ExtendedState 참조 가져오기
        preparedExtendedStateForReset.getVariables().clear(); // 내용 비우기 (선택적, reset에서 어차피 새로 설정될 수 있음)

        StateMachineContext<MfaState, MfaEvent> newContext = new DefaultStateMachineContext<>(
                targetState, null, null, preparedExtendedStateForReset, null, machineId
        );

        // 2. 상태 머신 리셋
        stateMachine.getStateMachineAccessor()
                .doWithAllRegions(access -> access.resetStateMachineReactively(newContext).block());
        log.debug("[MFA SM Service] [{}] SM 초기 상태({})로 리셋 완료.", machineId, targetState);

        // 3. ✨ 리셋 후 FactorContext를 ExtendedState에 다시 설정 (중요) ✨
        //    resetStateMachineReactively가 ExtendedState를 내부적으로 새로 만들거나 비울 수 있으므로,
        //    리셋 작업이 완료된 후의 ExtendedState에 FactorContext를 확실하게 넣어줍니다.
        if (factorContext != null) {
            ExtendedState currentExtendedStateAfterReset = stateMachine.getExtendedState(); // 리셋된 SM의 ExtendedState 참조
            StateContextHelper.setFactorContext(currentExtendedStateAfterReset, factorContext);
            log.debug("[MFA SM Service] [{}] 리셋 후 FactorContext (버전:{})를 ExtendedState에 설정.", machineId, factorContext.getVersion());
        }

        // 4. 리셋 후에는 항상 SM을 시작
        stateMachine.startReactively().block();
        log.debug("[MFA SM Service] [{}] 리셋된 SM 시작 완료.", machineId);
    }


    @Override
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        try {
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineProvider.getObject();
            resetStateMachine(stateMachine, sessionId, context.getCurrentState(), context); // 여기서 SM 시작 포함
            log.info("[MFA SM Service] [{}] SM 초기화 및 FactorContext와 동기화 완료. SM 상태: {}, FactorContext 버전: {}",
                    sessionId, stateMachine.getState().getId(), context.getVersion());

            sendEvent(MfaEvent.PRIMARY_AUTH_SUCCESS, context, request);

            log.debug("[MFA SM Service] [{}] SM 영속화 완료 (initialize). 최종 FactorContext 버전: {}", sessionId, context.getVersion());

        } catch (Exception e) {
            log.error("[MFA SM Service] [{}] SM 초기화 중 오류 발생.", sessionId, e);
            throw new MfaStateMachineException("Error during State Machine initialization for " + sessionId + ": " + e.getMessage(), e);
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

            Result result = sendEvent(stateMachine, message);

            if (result.eventAccepted()) {
                log.info("[MFA SM Service] [{}] 이벤트 {} 처리 후 SM 상태: {}", sessionId, message.getPayload(), result.smCurrentStateAfterEvent());
            } else {
                log.warn("[MFA SM Service] [{}] 이벤트 ({})가 현재 SM 상태 ({})에서 수락되지 않음.", sessionId, event, result.smCurrentStateAfterEvent());
            }

            if (result.contextFromSmAfterEvent() != null) {
                context.changeState(result.smCurrentStateAfterEvent());
                context.setVersion(result.contextFromSmAfterEvent().getVersion());
                context.getAttributes().clear();
                context.getAttributes().putAll(result.contextFromSmAfterEvent().getAttributes());
            } else {
                log.error("[MFA SM Service] [{}] 이벤트 처리 후 SM에서 FactorContext를 찾을 수 없음! 외부 context 상태만 SM 상태로 업데이트.", sessionId);
                context.changeState(result.smCurrentStateAfterEvent());
            }

            StateContextHelper.setFactorContext(stateMachine, context);

            StateMachine<MfaState, MfaEvent> machineToPersist = stateMachine;
            if (stateMachine instanceof Advised) { // 프록시 객체인지 확인
                try {
                    Object target = ((Advised) stateMachine).getTargetSource().getTarget();
                    if (target instanceof StateMachine) {
                        machineToPersist = (StateMachine<MfaState, MfaEvent>) ((Advised) target).getTargetSource().getTarget();
                        log.debug("[MFA SM Service] [{}] 원본 StateMachine 객체를 가져와서 영속화합니다.", sessionId);
                    } else {
                        log.warn("[MFA SM Service] [{}] 프록시의 원본 객체가 StateMachine 타입이 아닙니다. 프록시 객체를 그대로 사용합니다.", sessionId);
                    }
                } catch (Exception e) {
                    log.error("[MFA SM Service] [{}] 프록시에서 원본 StateMachine 객체를 가져오는 데 실패했습니다. 프록시 객체를 그대로 사용합니다.", sessionId, e);
                }
            }

            stateMachinePersister.persist(machineToPersist, sessionId);
            log.debug("[MFA SM Service] [{}] 상태 머신 영속화 완료. 최종 FactorContext 버전: {}", sessionId, context.getVersion());

            return result.eventAccepted();

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

    private static Result sendEvent(StateMachine<MfaState, MfaEvent> stateMachine, Message<MfaEvent> message) {

        Boolean accepted = stateMachine.sendEvent(Mono.just(message))
                .map(result -> result.getResultType() == StateMachineEventResult.ResultType.ACCEPTED)
                .blockFirst(Duration.ofSeconds(EVENT_PROCESSING_TIMEOUT_SECONDS));

        boolean eventAccepted = Boolean.TRUE.equals(accepted);

        MfaState smCurrentStateAfterEvent = stateMachine.getState().getId();
        FactorContext contextFromSmAfterEvent = StateContextHelper.getFactorContext(stateMachine);
        return new Result(eventAccepted, smCurrentStateAfterEvent, contextFromSmAfterEvent);
    }

    private record Result(boolean eventAccepted, MfaState smCurrentStateAfterEvent, FactorContext contextFromSmAfterEvent) {
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