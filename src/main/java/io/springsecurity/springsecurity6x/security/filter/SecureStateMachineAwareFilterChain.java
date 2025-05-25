package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

import static io.springsecurity.springsecurity6x.security.filter.MfaStepFilterWrapper.MIN_VERIFICATION_DELAY;

/**
 * State Machine 통합 FilterChain 래퍼
 * MFA 팩터 검증 과정을 State Machine과 통합하여 처리
 */
@Slf4j
public class SecureStateMachineAwareFilterChain implements FilterChain {

    private final FilterChainContext chainContext;
    private final SecurityContext securityContext;
    private final VerificationMetrics metrics;

    public SecureStateMachineAwareFilterChain(FilterChain delegate,
                                              FactorContext factorContext,
                                              HttpServletRequest request,
                                              MfaStateMachineIntegrator stateMachineIntegrator,
                                              long startTime) {
        this.chainContext = new FilterChainContext(delegate, request);
        this.securityContext = new SecurityContext(factorContext, stateMachineIntegrator);
        this.metrics = new VerificationMetrics(startTime);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        VerificationResult result = null;

        try {
            // 1. 검증 전 상태 캡처
            VerificationSnapshot beforeSnapshot = capturePreVerificationState();

            // 2. 실제 팩터 검증 실행
            executeFactorVerification(request, response);

            // 3. 검증 결과 분석
            result = analyzeVerificationResult(httpResponse, beforeSnapshot);

            // 4. State Machine 이벤트 전송
            handleVerificationResult(result);

        } catch (Exception e) {
            // 5. 예외 처리
            result = VerificationResult.failure("Exception during verification: " + e.getMessage());
            handleVerificationError(e);
            throw e;

        } finally {
            // 6. 메트릭 기록 및 보안 처리
            finalizeVerification(result);
        }
    }

    /**
     * 검증 전 상태 캡처
     */
    private VerificationSnapshot capturePreVerificationState() {
        return new VerificationSnapshot(
                securityContext.factorContext.getCurrentState(),
                securityContext.factorContext.getVersion(),
                securityContext.factorContext.getRetryCount(),
                System.currentTimeMillis()
        );
    }

    /**
     * 팩터 검증 실행
     */
    private void executeFactorVerification(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {

        // 검증 시작 로깅
        logVerificationStart();

        // 실제 필터 실행 (OTP, Passkey 등의 검증 로직)
        chainContext.delegate.doFilter(request, response);
    }

    /**
     * 검증 결과 분석
     */
    private VerificationResult analyzeVerificationResult(HttpServletResponse response,
                                                         VerificationSnapshot beforeSnapshot) {

        // 응답 상태 확인
        if (response.isCommitted()) {
            // 응답이 커밋됨 = 검증 필터가 직접 응답 처리
            return analyzeCommittedResponse(response, beforeSnapshot);
        }

        // 상태 변경 확인
        MfaState currentState = securityContext.factorContext.getCurrentState();
        if (currentState == beforeSnapshot.state()) {
            // 상태 미변경 = 검증 실패
            return VerificationResult.failure("State unchanged after verification");
        }

        // 버전 변경 확인 (동시성 체크)
        if (securityContext.factorContext.getVersion() == beforeSnapshot.version()) {
            // 버전 미변경 = 업데이트 없음
            return VerificationResult.failure("Version unchanged - no update occurred");
        }

        // 성공적인 상태 전이 확인
        if (isSuccessfulStateTransition(beforeSnapshot.state(), currentState)) {
            return VerificationResult.success();
        }

        return VerificationResult.failure("Invalid state transition");
    }

    /**
     * 커밋된 응답 분석
     */
    private VerificationResult analyzeCommittedResponse(HttpServletResponse response,
                                                        VerificationSnapshot beforeSnapshot) {
        // 응답 상태 코드로 성공/실패 판단
        int statusCode = response.getStatus();

        if (statusCode >= 200 && statusCode < 300) {
            // 2xx 응답 = 성공
            return VerificationResult.success();
        } else if (statusCode >= 400) {
            // 4xx, 5xx 응답 = 실패
            return VerificationResult.failure("HTTP " + statusCode);
        }

        // 상태 변경으로 판단
        MfaState currentState = securityContext.factorContext.getCurrentState();
        if (currentState != beforeSnapshot.state()) {
            return VerificationResult.success();
        }

        return VerificationResult.unknown();
    }

    /**
     * 검증 결과 처리
     */
    private void handleVerificationResult(VerificationResult result) {
        if (result.isFailure()) {
            sendVerificationFailedEvent(result.failureReason());
        } else if (result.isSuccess()) {
            // 성공 이벤트는 일반적으로 검증 필터 내부에서 전송됨
            logVerificationSuccess();
        }
    }

    /**
     * 검증 에러 처리
     */
    private void handleVerificationError(Exception e) {
        log.error("Factor verification error for session: {} - {}",
                securityContext.factorContext.getMfaSessionId(),
                e.getMessage(), e);

        // 에러 컨텍스트 저장
        securityContext.factorContext.setAttribute("lastVerificationError", e.getClass().getSimpleName());
        securityContext.factorContext.setAttribute("lastVerificationErrorMessage", e.getMessage());

        // 실패 이벤트 전송
        sendVerificationFailedEvent("Exception: " + e.getClass().getSimpleName());
    }

    /**
     * 검증 완료 처리
     */
    private void finalizeVerification(VerificationResult result) {
        // 메트릭 기록
        recordVerificationMetrics(result);

        // 타이밍 공격 방지
        enforceMinimumDelay();

        // 감사 로깅
        auditVerificationAttempt(result);
    }

    /**
     * 검증 실패 이벤트 전송
     */
    private void sendVerificationFailedEvent(String reason) {
        try {
            boolean sent = securityContext.stateMachineIntegrator.sendEvent(
                    MfaEvent.FACTOR_VERIFICATION_FAILED,
                    securityContext.factorContext,
                    chainContext.request
            );

            if (!sent) {
                log.warn("Failed to send FACTOR_VERIFICATION_FAILED event for session: {}",
                        securityContext.factorContext.getMfaSessionId());
            }
        } catch (Exception e) {
            log.error("Error sending verification failed event", e);
        }
    }

    /**
     * 성공적인 상태 전이 확인
     */
    private boolean isSuccessfulStateTransition(MfaState fromState, MfaState toState) {
        // 검증 대기 → 검증 완료
        if (fromState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION &&
                toState == MfaState.FACTOR_VERIFICATION_COMPLETED) {
            return true;
        }

        // 검증 중 → 검증 완료
        if (fromState == MfaState.FACTOR_VERIFICATION_PENDING &&
                toState == MfaState.FACTOR_VERIFICATION_COMPLETED) {
            return true;
        }

        // 추가 성공 패턴...
        return false;
    }

    /**
     * 메트릭 기록
     */
    private void recordVerificationMetrics(VerificationResult result) {
        long verificationTime = metrics.getElapsedTime();

        securityContext.factorContext.setAttribute("lastVerificationTime", verificationTime);
        securityContext.factorContext.setAttribute("lastVerificationResult", result.isSuccess());

        if (result.isFailure()) {
            int failureCount = securityContext.factorContext.incrementAttemptCount(
                    securityContext.factorContext.getCurrentProcessingFactor()
            );
            securityContext.factorContext.setAttribute("consecutiveFailures", failureCount);
        }
    }

    /**
     * 최소 지연 시간 보장 (타이밍 공격 방지)
     */
    private void enforceMinimumDelay() {
        long remainingDelay = MIN_VERIFICATION_DELAY - metrics.getElapsedTime();

        if (remainingDelay > 0) {
            try {
                Thread.sleep(remainingDelay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.debug("Minimum delay interrupted");
            }
        }
    }

    /**
     * 감사 로깅
     */
    private void auditVerificationAttempt(VerificationResult result) {
        String factorType = securityContext.factorContext.getCurrentProcessingFactor() != null ?
                securityContext.factorContext.getCurrentProcessingFactor().name() : "UNKNOWN";

        log.info("MFA Verification Audit - Session: {}, User: {}, Factor: {}, Result: {}, Duration: {}ms",
                securityContext.factorContext.getMfaSessionId(),
                securityContext.factorContext.getUsername(),
                factorType,
                result.isSuccess() ? "SUCCESS" : "FAILURE",
                metrics.getElapsedTime());
    }

    private void logVerificationStart() {
        log.debug("Starting factor verification for session: {}, factor: {}",
                securityContext.factorContext.getMfaSessionId(),
                securityContext.factorContext.getCurrentProcessingFactor());
    }

    private void logVerificationSuccess() {
        log.debug("Factor verification completed successfully for session: {}",
                securityContext.factorContext.getMfaSessionId());
    }

    /**
     * 필터 체인 컨텍스트
     */
    private record FilterChainContext(
            FilterChain delegate,
            HttpServletRequest request
    ) {}

    /**
     * 보안 컨텍스트
     */
    private record SecurityContext(
            FactorContext factorContext,
            MfaStateMachineIntegrator stateMachineIntegrator
    ) {}

    /**
     * 검증 메트릭
     */
    private static class VerificationMetrics {
        private final long startTime;

        VerificationMetrics(long startTime) {
            this.startTime = startTime;
        }

        long getElapsedTime() {
            return System.currentTimeMillis() - startTime;
        }
    }

    /**
     * 검증 전 상태 스냅샷
     */
    private record VerificationSnapshot(
            MfaState state,
            int version,
            int retryCount,
            long timestamp
    ) {}

    /**
     * 검증 결과
     */
    private static class VerificationResult {
        private final ResultType type;
        private final String failureReason;

        private VerificationResult(ResultType type, String failureReason) {
            this.type = type;
            this.failureReason = failureReason;
        }

        static VerificationResult success() {
            return new VerificationResult(ResultType.SUCCESS, null);
        }

        static VerificationResult failure(String reason) {
            return new VerificationResult(ResultType.FAILURE, reason);
        }

        static VerificationResult unknown() {
            return new VerificationResult(ResultType.UNKNOWN, null);
        }

        boolean isSuccess() { return type == ResultType.SUCCESS; }
        boolean isFailure() { return type == ResultType.FAILURE; }
        String failureReason() { return failureReason; }

        private enum ResultType { SUCCESS, FAILURE, UNKNOWN }
    }
}