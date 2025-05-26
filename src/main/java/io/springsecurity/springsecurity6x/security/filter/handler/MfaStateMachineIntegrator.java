package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * 완전 일원화된 MfaStateMachineIntegrator
 * - State Machine을 완전한 단일 진실의 원천으로 사용
 * - ContextPersistence 의존성 완전 제거
 * - 모든 상태 관리를 State Machine Service를 통해 수행
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineIntegrator {

    private final MfaStateMachineService stateMachineService;

    /**
     * 완전 일원화: State Machine 초기화
     * - FactorContext와 State Machine을 동시에 초기화
     */
    public void initializeStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.info("Initializing unified State Machine for session: {}", sessionId);

        try {
            // State Machine 초기화 (FactorContext도 함께 저장됨)
            stateMachineService.initializeStateMachine(context, request);

            // 세션에 MFA 세션 ID 매핑 저장 (최소한의 매핑만)
            HttpSession session = request.getSession(true);
            session.setAttribute("MFA_SESSION_ID", sessionId);

            log.info("Unified State Machine initialized successfully for session: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to initialize unified State Machine for session: {}", sessionId, e);
            throw new StateMachineIntegrationException("State Machine initialization failed", e);
        }
    }

    /**
     * 완전 일원화: 이벤트 전송
     * - State Machine에서 FactorContext 자동 로드 및 업데이트
     */
    public boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.debug("Sending event {} to unified State Machine for session: {}", event, sessionId);

        try {
            // State Machine Service를 통해 이벤트 전송 (컨텍스트 자동 동기화)
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
     * 완전 일원화: State Machine과 FactorContext 동기화
     * - State Machine이 진실의 원천이므로 단방향 동기화
     */
    public void syncStateWithStateMachine(FactorContext context, HttpServletRequest request) {
        String sessionId = context.getMfaSessionId();
        log.debug("Syncing FactorContext with unified State Machine for session: {}", sessionId);

        try {
            // State Machine에서 최신 컨텍스트 로드
            FactorContext latestContext = stateMachineService.getFactorContext(sessionId);

            if (latestContext != null) {
                // State Machine의 상태를 FactorContext에 단방향 동기화
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
     * 완전 일원화: 현재 상태 조회
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
     * 완전 일원화: FactorContext 로드
     * - State Machine에서만 로드
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
     * 완전 일원화: FactorContext 저장
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
     * 완전 일원화: State Machine 해제
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
     * 완전 일원화: 요청에서 FactorContext 로드
     * - 세션에서 MFA 세션 ID를 가져와서 State Machine에서 로드
     */
    public FactorContext loadFactorContextFromRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in session. Cannot load FactorContext.");
            return null;
        }

        return loadFactorContext(mfaSessionId);
    }

    /**
     * 완전 일원화: 요청에서 현재 상태 조회
     */
    public MfaState getCurrentStateFromRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return MfaState.NONE;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            return MfaState.NONE;
        }

        return getCurrentState(mfaSessionId);
    }

    /**
     * 완전 일원화: 세션 유효성 검증
     * - State Machine과 세션의 일관성 확인
     */
    public boolean isValidMfaSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            return false;
        }

        // State Machine에서 컨텍스트 존재 여부 확인
        FactorContext context = loadFactorContext(mfaSessionId);
        return context != null && !context.getCurrentState().isTerminal();
    }

    /**
     * 완전 일원화: 세션 정리
     * - State Machine과 HTTP 세션 모두 정리
     */
    public void cleanupSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId != null) {
            // State Machine 해제
            releaseStateMachine(mfaSessionId);

            // HTTP 세션에서 MFA 세션 ID 제거
            session.removeAttribute("MFA_SESSION_ID");

            log.debug("Session cleanup completed for MFA session: {}", mfaSessionId);
        }
    }

    /**
     * 완전 일원화: 상태만 업데이트 (성능 최적화)
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
     * State Machine에서 FactorContext로 단방향 동기화
     * - State Machine이 진실의 원천
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

        // 중요한 비즈니스 속성들만 동기화 (시스템 속성 제외)
        source.getAttributes().forEach((key, value) -> {
            if (isBusinessAttribute(key)) {
                target.setAttribute(key, value);
            }
        });
    }

    /**
     * 비즈니스 속성인지 확인 (시스템 속성 제외)
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