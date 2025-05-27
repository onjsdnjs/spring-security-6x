package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Repository 패턴 기반 완전 일원화된 MfaStateMachineIntegrator
 * 개선사항:
 * - 동기화 최적화: 불필요한 중복 동기화 방지
 * - 이벤트 처리 표준화: 일관된 처리 패턴 적용
 * - 성능 개선: 조건부 동기화 및 캐싱 적용
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;
    private final MfaSessionRepository sessionRepository;
    private final AuthContextProperties properties;

    // 개선: 동기화 상태 추적을 위한 캐시
    private final Map<String, Long> lastSyncTimestamp = new ConcurrentHashMap<>();
    private final Map<String, Integer> lastSyncVersion = new ConcurrentHashMap<>();
    private final long SYNC_INTERVAL_MS = 1000; // 1초 간격으로 동기화 제한

    @PostConstruct
    public void initialize() {
        sessionRepository.setSessionTimeout(properties.getMfa().getSessionTimeout());
        log.info("MfaStateMachineIntegrator initialized with {} repository - Enhanced with sync optimization",
                sessionRepository.getRepositoryType());
    }

    /**
     * 완전 일원화: State Machine 초기화 (기존 메서드 시그니처 완전 유지)
     */
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing unified State Machine for session: {} using {} repository",
                sessionId, sessionRepository.getRepositoryType());

        try {
            // State Machine 초기화 (FactorContext도 함께 저장됨)
            stateMachineService.initializeStateMachine(context, request);

            // Repository를 통한 세션 저장
            sessionRepository.storeSession(sessionId, request, null);

            // 개선: 초기화 후 동기화 상태 기록
            updateSyncState(sessionId, context.getVersion());

            log.info("Unified State Machine initialized successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", sessionId, e);
            throw new StateMachineIntegrationException("State Machine initialization failed", e);
        }
    }

    public void initializeStateMachine(FactorContext context, HttpServletRequest request, HttpServletResponse response) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing unified State Machine for session: {} using {} repository",
                sessionId, sessionRepository.getRepositoryType());

        try {
            stateMachineService.initializeStateMachine(context, request);
            sessionRepository.storeSession(sessionId, request, response);

            // 개선: 초기화 후 동기화 상태 기록
            updateSyncState(sessionId, context.getVersion());

            log.info("Unified State Machine initialized successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", sessionId, e);
            throw new StateMachineIntegrationException("State Machine initialization failed", e);
        }
    }

    /**
     * 완전 일원화: 이벤트 전송 (개선된 실패 처리)
     */
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.debug("Sending event {} to unified State Machine for session: {}", event, sessionId);

        try {
            sessionRepository.refreshSession(sessionId);

            // 개선: 이벤트 전송 전 상태 검증
            if (!isValidEventForCurrentState(event, context.getCurrentState())) {
                log.warn("Event {} is not valid for current state {} in session: {}",
                        event, context.getCurrentState(), sessionId);
                return false;
            }

            boolean accepted = stateMachineService.sendEvent(event, context, request);

            if (accepted) {
                // 개선: 성공한 이벤트 후 동기화 상태 업데이트
                updateSyncState(sessionId, context.getVersion());
                log.debug("Event {} accepted by unified State Machine for session: {}", event, sessionId);
            } else {
                // 개선: 구체적인 거부 사유 분석
                String rejectionReason = analyzeEventRejectionReason(context, event);
                log.warn("Event {} rejected by unified State Machine for session: {} - Reason: {}",
                        event, sessionId, rejectionReason);
            }

            return accepted;
        } catch (Exception e) {
            log.error("Failed to send event {} to unified State Machine for session: {}", event, sessionId, e);
            return false;
        }
    }

    /**
     * 개선: 조건부 동기화 - 성능 최적화
     */
    public void syncStateWithStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();

        // 개선: 최근 동기화 시간 및 버전 확인
        if (!needsSync(sessionId, context.getVersion())) {
            log.debug("Skipping sync - context already up-to-date for session: {}", sessionId);
            return;
        }

        log.debug("Syncing FactorContext with unified State Machine for session: {}", sessionId);

        try {
            FactorContext latestContext = stateMachineService.getFactorContext(sessionId);

            if (latestContext != null) {
                // 개선: 버전 비교로 동기화 필요성 재확인
                if (context.getVersion() >= latestContext.getVersion()) {
                    log.debug("Context version already up-to-date for session: {} (current: {}, latest: {})",
                            sessionId, context.getVersion(), latestContext.getVersion());
                    updateSyncState(sessionId, context.getVersion());
                    return;
                }

                syncFactorContextFromStateMachine(context, latestContext);
                updateSyncState(sessionId, latestContext.getVersion());

                log.debug("FactorContext synchronized: session={}, oldVersion={}, newVersion={}",
                        sessionId, context.getVersion(), latestContext.getVersion());
            } else {
                log.warn("No context found in unified State Machine for session: {}", sessionId);
            }
        } catch (Exception e) {
            log.error("Failed to sync with unified State Machine for session: {}", sessionId, e);
        }
    }

    /**
     * 완전 일원화: 현재 상태 조회 (캐시 활용)
     */
    public MfaState getCurrentState(String sessionId) {
        try {
            return stateMachineService.getCurrentState(sessionId);
        } catch (Exception e) {
            log.error("Failed to get current state from unified State Machine for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    public FactorContext loadFactorContext(String sessionId) {
        try {
            return stateMachineService.getFactorContext(sessionId);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from unified State Machine for session: {}", sessionId, e);
            return null;
        }
    }

    public void saveFactorContext(FactorContext context) {
        try {
            stateMachineService.saveFactorContext(context);
            // 개선: 저장 후 동기화 상태 업데이트
            updateSyncState(context.getMfaSessionId(), context.getVersion());

            log.debug("FactorContext saved to unified State Machine: session={}, state={}, version={}",
                    context.getMfaSessionId(), context.getCurrentState(), context.getVersion());
        } catch (Exception e) {
            log.error("Failed to save FactorContext to unified State Machine for session: {}",
                    context.getMfaSessionId(), e);
        }
    }

    public void releaseStateMachine(String sessionId) {
        log.info("Releasing unified State Machine for session: {}", sessionId);

        try {
            stateMachineService.releaseStateMachine(sessionId);

            // 개선: 세션 해제 시 동기화 상태도 정리
            cleanupSyncState(sessionId);

            log.info("Unified State Machine released successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to release unified State Machine for session: {}", sessionId, e);
        }
    }

    public FactorContext loadFactorContextFromRequest(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in {}. Cannot load FactorContext.",
                    sessionRepository.getRepositoryType());
            return null;
        }

        if (!sessionRepository.existsSession(mfaSessionId)) {
            log.trace("MFA session {} not found in {}. Cannot load FactorContext.",
                    mfaSessionId, sessionRepository.getRepositoryType());
            return null;
        }

        return loadFactorContext(mfaSessionId);
    }

    public MfaState getCurrentStateFromRequest(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            return MfaState.NONE;
        }

        if (!sessionRepository.existsSession(mfaSessionId)) {
            return MfaState.NONE;
        }

        return getCurrentState(mfaSessionId);
    }

    public boolean isValidMfaSession(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            return false;
        }

        if (!sessionRepository.existsSession(mfaSessionId)) {
            return false;
        }

        FactorContext context = loadFactorContext(mfaSessionId);
        return context != null && !context.getCurrentState().isTerminal();
    }

    public void cleanupSession(HttpServletRequest request) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId != null) {
            releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, null);

            log.debug("Session cleanup completed for MFA session: {} using {} repository",
                    mfaSessionId, sessionRepository.getRepositoryType());
        }
    }

    public void cleanupSession(HttpServletRequest request, HttpServletResponse response) {
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId != null) {
            releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, response);

            log.debug("Session cleanup with response completed for MFA session: {} using {} repository",
                    mfaSessionId, sessionRepository.getRepositoryType());
        }
    }

    public boolean updateStateOnly(String sessionId, MfaState newState) {
        try {
            return stateMachineService.updateStateOnly(sessionId, newState);
        } catch (Exception e) {
            log.error("Failed to update state only for session: {}", sessionId, e);
            return false;
        }
    }

    public String getSessionRepositoryInfo() {
        return String.format("Repository: %s, Timeout: %s",
                sessionRepository.getRepositoryType(),
                properties.getMfa().getSessionTimeout());
    }

    // === 개선된 내부 메서드들 ===

    /**
     * 개선: 동기화 필요성 판단
     */
    private boolean needsSync(String sessionId, int currentVersion) {
        Long lastSync = lastSyncTimestamp.get(sessionId);
        Integer lastVersion = lastSyncVersion.get(sessionId);

        long now = System.currentTimeMillis();

        // 시간 기반 체크
        if (lastSync != null && (now - lastSync) < SYNC_INTERVAL_MS) {
            return false;
        }

        // 버전 기반 체크
        if (lastVersion != null && currentVersion <= lastVersion) {
            return false;
        }

        return true;
    }

    /**
     * 개선: 동기화 상태 업데이트
     */
    private void updateSyncState(String sessionId, int version) {
        lastSyncTimestamp.put(sessionId, System.currentTimeMillis());
        lastSyncVersion.put(sessionId, version);
    }

    /**
     * 개선: 동기화 상태 정리
     */
    private void cleanupSyncState(String sessionId) {
        lastSyncTimestamp.remove(sessionId);
        lastSyncVersion.remove(sessionId);
    }

    /**
     * 개선: 이벤트 유효성 검증
     */
    private boolean isValidEventForCurrentState(MfaEvent event, MfaState currentState) {
        // 기본적인 이벤트-상태 유효성 검증 로직
        switch (event) {
            case MFA_NOT_REQUIRED:
                return currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
            case MFA_REQUIRED_SELECT_FACTOR:
                return currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
            case FACTOR_SELECTED:
                return currentState == MfaState.AWAITING_FACTOR_SELECTION;
            case INITIATE_CHALLENGE:
                return currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
            case SUBMIT_FACTOR_CREDENTIAL:
                return currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
            case FACTOR_VERIFIED_SUCCESS:
                return currentState == MfaState.FACTOR_VERIFICATION_PENDING ||
                        currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
            case FACTOR_VERIFICATION_FAILED:
                return currentState == MfaState.FACTOR_VERIFICATION_PENDING ||
                        currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
            default:
                return true; // 기타 이벤트는 기본적으로 허용
        }
    }

    /**
     * 개선: 이벤트 거부 사유 분석
     */
    private String analyzeEventRejectionReason(FactorContext context, MfaEvent event) {
        MfaState currentState = context.getCurrentState();

        if (currentState.isTerminal()) {
            return String.format("State %s is terminal - no further events allowed", currentState);
        }

        switch (currentState) {
            case MFA_SESSION_EXPIRED:
                return "MFA session has expired";
            case MFA_RETRY_LIMIT_EXCEEDED:
            case MFA_FAILED_TERMINAL:
                return "MFA has failed and reached terminal state";
            case NONE:
                return "State Machine not properly initialized";
            default:
                return String.format("Event %s not valid for current state %s", event, currentState);
        }
    }

    /**
     * State Machine에서 FactorContext로 단방향 동기화
     */
    private void syncFactorContextFromStateMachine(FactorContext target, FactorContext source) {
        // 상태 동기화
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        // 버전 동기화
        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        // 현재 처리 정보 동기화
        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setCurrentFactorOptions(source.getCurrentFactorOptions());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        // 재시도 및 에러 정보 동기화
        target.setRetryCount(source.getRetryCount());
        if (source.getLastError() != null) {
            target.setLastError(source.getLastError());
        }

        // 중요한 비즈니스 속성들만 동기화
        source.getAttributes().forEach((key, value) -> {
            if (isBusinessAttribute(key)) {
                target.setAttribute(key, value);
            }
        });
    }

    /**
     * 비즈니스 속성인지 확인
     */
    private boolean isBusinessAttribute(String key) {
        return !key.startsWith("_") &&
                !"currentState".equals(key) &&
                !"version".equals(key) &&
                !"lastUpdated".equals(key) &&
                !"stateHash".equals(key) &&
                !"storageType".equals(key);
    }

    /**
     * State Machine 통합 예외 클래스
     */
    public static class StateMachineIntegrationException extends RuntimeException {
        public StateMachineIntegrationException(String message) {
            super(message);
        }

        public StateMachineIntegrationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}