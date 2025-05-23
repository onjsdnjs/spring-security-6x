package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Component;

/**
 * MFA 이벤트 어댑터 구현체
 * FactorContext와 이벤트 간의 매핑 및 정책 적용을 담당
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaEventAdapterImpl implements MfaEventAdapter {

    private final AuthContextProperties authContextProperties;

    @Override
    public MfaEvent determineEvent(String action, FactorContext context) {
        if (action == null) {
            log.warn("Action is null, returning USER_ABORTED_MFA event");
            return MfaEvent.USER_ABORTED_MFA;
        }

        log.debug("Determining event for action: {} in session: {}",
                action, context.getMfaSessionId());

        // 액션 문자열을 이벤트로 매핑
        MfaEvent event = mapActionToEvent(action.toUpperCase());

        // 컨텍스트 기반 이벤트 조정
        event = adjustEventBasedOnContext(event, context);

        log.debug("Determined event: {} for action: {}", event, action);
        return event;
    }

    @Override
    public boolean canTriggerEvent(MfaEvent event, FactorContext context) {
        // 기본적으로 모든 이벤트 허용
        boolean canTrigger = true;

        // 재시도 제한 확인
        if (isRetryEvent(event)) {
            canTrigger = context.getRetryCount() < getMaxRetries();
            if (!canTrigger) {
                log.warn("Retry limit exceeded for session: {}", context.getMfaSessionId());
            }
        }

        // 세션 만료 확인
        if (isSessionExpired(context)) {
            log.warn("Session expired for session: {}", context.getMfaSessionId());
            return false;
        }

        return canTrigger;
    }

    @Override
    public int getMaxRetries() {
        // 기본값 3
        return 3;
    }

    @Override
    public long calculateSessionDuration(FactorContext context) {
        long createdAt = context.getCreatedAt(); // long 타입 반환
        long now = System.currentTimeMillis();
        return (now - createdAt) / 1000; // 초 단위로 반환
    }

    @Override
    public Message<MfaEvent> toStateMachineMessage(MfaEvent event, FactorContext context) {
        return MessageBuilder
                .withPayload(event)
                .setHeader("mfaSessionId", context.getMfaSessionId())
                .setHeader("username", context.getUsername())
                .setHeader("timestamp", System.currentTimeMillis())
                .setHeader("authentication", context.getPrimaryAuthentication())
                .build();
    }

    /**
     * 액션 문자열을 MfaEvent로 매핑
     */
    private MfaEvent mapActionToEvent(String action) {
        switch (action) {
            case "START":
            case "INITIATE":
                return MfaEvent.PRIMARY_AUTH_SUCCESS;

            case "SELECT":
            case "CHOOSE_FACTOR":
                return MfaEvent.FACTOR_SELECTED;

            case "SEND_CHALLENGE":
            case "REQUEST_CODE":
                return MfaEvent.INITIATE_CHALLENGE;

            case "VERIFY":
            case "SUBMIT_CODE":
                return MfaEvent.SUBMIT_FACTOR_CREDENTIAL;

            case "CANCEL":
            case "ABORT":
                return MfaEvent.USER_ABORTED_MFA;

            case "TIMEOUT":
            case "EXPIRE":
                return MfaEvent.SESSION_TIMEOUT;

            default:
                // MfaEvent enum에 정의된 값과 직접 매칭 시도
                try {
                    return MfaEvent.valueOf(action);
                } catch (IllegalArgumentException e) {
                    log.warn("Unknown action: {}", action);
                    return MfaEvent.SYSTEM_ERROR;
                }
        }
    }

    /**
     * 컨텍스트 기반으로 이벤트 조정
     */
    private MfaEvent adjustEventBasedOnContext(MfaEvent event, FactorContext context) {
        // 검증 시도 이벤트를 성공/실패로 구분
        if (event == MfaEvent.SUBMIT_FACTOR_CREDENTIAL) {
            // 실제 검증 결과에 따라 이벤트 조정 (여기서는 예시)
            // 실제 구현에서는 검증 서비스의 결과를 확인해야 함
            Boolean verificationResult = (Boolean) context.getAttribute("lastVerificationResult");

            if (verificationResult != null) {
                return verificationResult ?
                        MfaEvent.FACTOR_VERIFIED_SUCCESS :
                        MfaEvent.FACTOR_VERIFICATION_FAILED;
            }
        }

        // 세션 만료 확인
        if (isSessionExpired(context)) {
            return MfaEvent.SESSION_TIMEOUT;
        }

        return event;
    }

    /**
     * 재시도 관련 이벤트인지 확인
     */
    private boolean isRetryEvent(MfaEvent event) {
        return event == MfaEvent.SUBMIT_FACTOR_CREDENTIAL ||
                event == MfaEvent.FACTOR_VERIFICATION_FAILED ||
                event == MfaEvent.RETRY_REQUESTED;
    }

    /**
     * 세션 만료 여부 확인
     */
    private boolean isSessionExpired(FactorContext context) {
        // 세션 타임아웃 설정값 가져오기 (기본 30분)
        int sessionTimeoutMinutes = 30;

        long createdAt = context.getCreatedAt();
        long now = System.currentTimeMillis();
        long durationMinutes = (now - createdAt) / (1000 * 60);

        return durationMinutes > sessionTimeoutMinutes;
    }

    /**
     * 이벤트에 대한 설명 가져오기
     */
    public String getEventDescription(MfaEvent event) {
        return switch (event) {
            case PRIMARY_AUTH_SUCCESS -> "Primary authentication successful";
            case FACTOR_SELECTED -> "Authentication factor selected";
            case INITIATE_CHALLENGE -> "Challenge initiation requested";
            case FACTOR_VERIFIED_SUCCESS -> "Factor verification successful";
            case FACTOR_VERIFICATION_FAILED -> "Factor verification failed";
            case ALL_REQUIRED_FACTORS_COMPLETED -> "All required factors completed";
            case USER_ABORTED_MFA -> "MFA process cancelled by user";
            case SESSION_TIMEOUT -> "MFA session expired";
            default -> "Event: " + event;
        };
    }
}