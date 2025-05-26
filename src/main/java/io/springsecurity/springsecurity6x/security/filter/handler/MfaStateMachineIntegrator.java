package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.properties.MfaSettings;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Repository 패턴 기반 완전 일원화된 MfaStateMachineIntegrator
 * - 기존 클래스 구조와 메서드 시그니처 완전 유지
 * - 설정에 따라 HTTP Session, Redis, Memory 등 자동 선택
 * - State Machine을 완전한 단일 진실의 원천으로 사용 (기존 유지)
 * - ContextPersistence 의존성 완전 제거 (기존 유지)
 * - 모든 상태 관리를 State Machine Service를 통해 수행 (기존 유지)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;
    private final MfaSessionRepository sessionRepository;
    private final AuthContextProperties properties;

    @PostConstruct
    public void initialize() {
        // MfaSettings의 타임아웃을 Repository에 설정
        sessionRepository.setSessionTimeout(properties.getMfa().getSessionTimeout());

        log.info("MfaStateMachineIntegrator initialized with {} repository",
                sessionRepository.getRepositoryType());
    }

    /**
     * 완전 일원화: State Machine 초기화 (기존 메서드 시그니처 완전 유지)
     * - FactorContext와 State Machine을 동시에 초기화
     */
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing unified State Machine for session: {} using {} repository",
                sessionId, sessionRepository.getRepositoryType());

        try {
            // State Machine 초기화 (FactorContext도 함께 저장됨) (기존 유지)
            stateMachineService.initializeStateMachine(context, request);

            // Repository를 통한 세션 저장 (구현체에 따라 HTTP Session 또는 Redis 등)
            sessionRepository.storeSession(sessionId, request, null);

            log.info("Unified State Machine initialized successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", sessionId, e);
            throw new StateMachineIntegrationException("State Machine initialization failed", e);
        }
    }

    /**
     * 완전 일원화: State Machine 초기화 (HttpServletResponse 추가 오버로드)
     * - Repository가 쿠키 관리를 지원하는 경우 활용
     */
    public void initializeStateMachine(FactorContext context, HttpServletRequest request, HttpServletResponse response) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing unified State Machine for session: {} using {} repository",
                sessionId, sessionRepository.getRepositoryType());

        try {
            // State Machine 초기화 (FactorContext도 함께 저장됨) (기존 유지)
            stateMachineService.initializeStateMachine(context, request);

            // Repository를 통한 세션 저장 (response 포함으로 쿠키 설정 가능)
            sessionRepository.storeSession(sessionId, request, response);

            log.info("Unified State Machine initialized successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", sessionId, e);
            throw new StateMachineIntegrationException("State Machine initialization failed", e);
        }
    }

    /**
     * 완전 일원화: 이벤트 전송 (기존 메서드 시그니처 완전 유지)
     * - State Machine에서 FactorContext 자동 로드 및 업데이트
     */
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.debug("Sending event {} to unified State Machine for session: {}", event, sessionId);

        try {
            // Repository를 통한 세션 활동 갱신
            sessionRepository.refreshSession(sessionId);

            // State Machine Service를 통해 이벤트 전송 (컨텍스트 자동 동기화) (기존 유지)
            boolean accepted = stateMachineService.sendEvent(event, context, request);

            if (accepted) {
                log.debug("Event {} accepted by unified State Machine for session: {}", event, sessionId);
            } else {
                log.warn("Event {} rejected by unified State Machine for session: {} in current state",
                        event, sessionId);
            }

            return accepted;
        } catch (Exception e) {
            log.error("Failed to send event {} to unified State Machine for session: {}", event, sessionId, e);
            return false;
        }
    }

    /**
     * 완전 일원화: State Machine과 FactorContext 동기화 (기존 메서드 시그니처 완전 유지)
     * - State Machine이 진실의 원천이므로 단방향 동기화
     */
    public void syncStateWithStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.debug("Syncing FactorContext with unified State Machine for session: {}", sessionId);

        try {
            // State Machine에서 최신 컨텍스트 로드 (기존 유지)
            FactorContext latestContext = stateMachineService.getFactorContext(sessionId);

            if (latestContext != null) {
                // State Machine의 상태를 FactorContext에 단방향 동기화 (기존 유지)
                syncFactorContextFromStateMachine(context, latestContext);
                log.debug("FactorContext synchronized with unified State Machine: session={}, state={}, version={}",
                        sessionId, context.getCurrentState(), context.getVersion());
            } else {
                log.warn("No context found in unified State Machine for session: {}", sessionId);
            }
        } catch (Exception e) {
            log.error("Failed to sync with unified State Machine for session: {}", sessionId, e);
        }
    }

    /**
     * 완전 일원화: 현재 상태 조회 (기존 메서드 시그니처 완전 유지)
     * - State Machine에서 직접 조회
     */
    public MfaState getCurrentState(String sessionId) {
        try {
            return stateMachineService.getCurrentState(sessionId);
        } catch (Exception e) {
            log.error("Failed to get current state from unified State Machine for session: {}", sessionId, e);
            return MfaState.NONE;
        }
    }

    /**
     * 완전 일원화: FactorContext 로드 (기존 메서드 시그니처 완전 유지)
     * - State Machine 에서만 로드
     */
    public FactorContext loadFactorContext(String sessionId) {
        try {
            return stateMachineService.getFactorContext(sessionId);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from unified State Machine for session: {}", sessionId, e);
            return null;
        }
    }

    /**
     * 완전 일원화: FactorContext 저장 (기존 메서드 시그니처 완전 유지)
     * - State Machine 에만 저장
     */
    public void saveFactorContext(FactorContext context) {
        try {
            stateMachineService.saveFactorContext(context);
            log.debug("FactorContext saved to unified State Machine: session={}, state={}, version={}",
                    context.getMfaSessionId(), context.getCurrentState(), context.getVersion());
        } catch (Exception e) {
            log.error("Failed to save FactorContext to unified State Machine for session: {}",
                    context.getMfaSessionId(), e);
        }
    }

    /**
     * 완전 일원화: State Machine 해제 (기존 메서드 시그니처 완전 유지)
     * - 세션 정리도 함께 수행
     */
    public void releaseStateMachine(String sessionId) {
        log.info("Releasing unified State Machine for session: {}", sessionId);

        try {
            stateMachineService.releaseStateMachine(sessionId);
            log.info("Unified State Machine released successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to release unified State Machine for session: {}", sessionId, e);
        }
    }

    /**
     * 완전 일원화: 요청에서 FactorContext 로드 (기존 메서드 시그니처 완전 유지)
     * - Repository를 통해 MFA 세션 ID를 가져와서 State Machine에서 로드
     */
    public FactorContext loadFactorContextFromRequest(HttpServletRequest request) {
        // Repository를 통한 MFA 세션 ID 조회 (구현체에 따라 HTTP Session, Redis, Memory 등)
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in {}. Cannot load FactorContext.",
                    sessionRepository.getRepositoryType());
            return null;
        }

        // Repository에서 세션 존재 여부 확인
        if (!sessionRepository.existsSession(mfaSessionId)) {
            log.trace("MFA session {} not found in {}. Cannot load FactorContext.",
                    mfaSessionId, sessionRepository.getRepositoryType());
            return null;
        }

        return loadFactorContext(mfaSessionId);
    }

    /**
     * 완전 일원화: 요청에서 현재 상태 조회 (기존 메서드 시그니처 완전 유지)
     */
    public MfaState getCurrentStateFromRequest(HttpServletRequest request) {
        // Repository를 통한 MFA 세션 ID 조회
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            return MfaState.NONE;
        }

        // Repository에서 세션 존재 여부 확인
        if (!sessionRepository.existsSession(mfaSessionId)) {
            return MfaState.NONE;
        }

        return getCurrentState(mfaSessionId);
    }

    /**
     * 완전 일원화: 세션 유효성 검증 (기존 메서드 시그니처 완전 유지)
     * - State Machine과 Repository 세션의 일관성 확인
     */
    public boolean isValidMfaSession(HttpServletRequest request) {
        // Repository를 통한 MFA 세션 ID 조회
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            return false;
        }

        // Repository에서 세션 존재 여부 확인
        if (!sessionRepository.existsSession(mfaSessionId)) {
            return false;
        }

        // State Machine에서 컨텍스트 존재 여부 확인 (기존 유지)
        FactorContext context = loadFactorContext(mfaSessionId);
        return context != null && !context.getCurrentState().isTerminal();
    }

    /**
     * 완전 일원화: 세션 정리 (기존 메서드 시그니처 완전 유지)
     * - State Machine과 Repository 세션 모두 정리
     */
    public void cleanupSession(HttpServletRequest request) {
        // Repository를 통한 MFA 세션 ID 조회
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId != null) {
            // State Machine 해제 (기존 유지)
            releaseStateMachine(mfaSessionId);

            // Repository를 통한 세션 제거
            sessionRepository.removeSession(mfaSessionId, request, null);

            log.debug("Session cleanup completed for MFA session: {} using {} repository",
                    mfaSessionId, sessionRepository.getRepositoryType());
        }
    }

    /**
     * 완전 일원화: 세션 정리 (HttpServletResponse 추가 오버로드)
     * - Repository가 쿠키 관리를 지원하는 경우 활용
     */
    public void cleanupSession(HttpServletRequest request, HttpServletResponse response) {
        // Repository를 통한 MFA 세션 ID 조회
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId != null) {
            // State Machine 해제 (기존 유지)
            releaseStateMachine(mfaSessionId);

            // Repository를 통한 세션 제거 (response 포함으로 쿠키 무효화 가능)
            sessionRepository.removeSession(mfaSessionId, request, response);

            log.debug("Session cleanup with response completed for MFA session: {} using {} repository",
                    mfaSessionId, sessionRepository.getRepositoryType());
        }
    }

    /**
     * 완전 일원화: 상태만 업데이트 (성능 최적화) (기존 메서드 시그니처 완전 유지)
     * - 빈번한 상태 변경 시 사용
     */
    public boolean updateStateOnly(String sessionId, MfaState newState) {
        try {
            return stateMachineService.updateStateOnly(sessionId, newState);
        } catch (Exception e) {
            log.error("Failed to update state only for session: {}", sessionId, e);
            return false;
        }
    }

    /**
     * Repository 정보 조회 (디버깅/모니터링용)
     */
    public String getSessionRepositoryInfo() {
        return String.format("Repository: %s, Timeout: %s",
                sessionRepository.getRepositoryType(),
                properties.getMfa().getSessionTimeout());
    }

    // === 기존 유틸리티 메서드들 완전 유지 ===

    /**
     * State Machine에서 FactorContext로 단방향 동기화 (기존 메서드 완전 유지)
     * - State Machine이 진실의 원천
     */
    private void syncFactorContextFromStateMachine(FactorContext target, FactorContext source) {
        // 상태 동기화 (기존 유지)
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        // 버전 동기화 (기존 유지)
        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        // 현재 처리 정보 동기화 (기존 유지)
        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setCurrentFactorOptions(source.getCurrentFactorOptions());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        // 재시도 및 에러 정보 동기화 (기존 유지)
        target.setRetryCount(source.getRetryCount());
        if (source.getLastError() != null) {
            target.setLastError(source.getLastError());
        }

        // 중요한 비즈니스 속성들만 동기화 (시스템 속성 제외) (기존 유지)
        source.getAttributes().forEach((key, value) -> {
            if (isBusinessAttribute(key)) {
                target.setAttribute(key, value);
            }
        });
    }

    /**
     * 비즈니스 속성인지 확인 (시스템 속성 제외) (기존 메서드 완전 유지)
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
     * State Machine 통합 예외 클래스 (기존 클래스 완전 유지)
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