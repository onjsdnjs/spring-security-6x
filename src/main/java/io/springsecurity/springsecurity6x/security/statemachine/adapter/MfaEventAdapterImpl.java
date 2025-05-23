package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * MfaEvent와 State Machine Message 간의 변환 어댑터 구현체
 */
@Slf4j
@Component
public class MfaEventAdapterImpl implements MfaEventAdapter {

    // Message Header 키 상수
    private static final String HEADER_SESSION_ID = "sessionId";
    private static final String HEADER_USERNAME = "username";
    private static final String HEADER_FACTOR_TYPE = "factorType";
    private static final String HEADER_TIMESTAMP = "timestamp";
    private static final String HEADER_SOURCE = "source";

    @Override
    public Message<MfaEvent> toStateMachineMessage(MfaEvent event, FactorContext context) {
        log.debug("Converting MfaEvent {} to State Machine message", event);

        Map<String, Object> headers = new HashMap<>();

        // 컨텍스트 정보를 헤더에 포함
        headers.put(HEADER_SESSION_ID, context.getMfaSessionId());
        headers.put(HEADER_USERNAME, context.getUsername());
        headers.put(HEADER_TIMESTAMP, System.currentTimeMillis());
        headers.put(HEADER_SOURCE, "MfaEventAdapter");

        // 현재 처리 중인 팩터 정보
        if (context.getCurrentProcessingFactor() != null) {
            headers.put(HEADER_FACTOR_TYPE, context.getCurrentProcessingFactor().name());
        }

        // 이벤트별 추가 정보
        enrichHeadersForEvent(event, context, headers);

        Message<MfaEvent> message = MessageBuilder
                .withPayload(event)
                .copyHeaders(headers)
                .build();

        log.debug("Created State Machine message with {} headers", headers.size());
        return message;
    }

    @Override
    public MfaEvent extractMfaEvent(Message<?> message) {
        if (message.getPayload() instanceof MfaEvent) {
            return (MfaEvent) message.getPayload();
        }

        // 페이로드가 MfaEvent가 아닌 경우 처리
        log.warn("Message payload is not MfaEvent type: {}", message.getPayload().getClass());
        return null;
    }

    /**
     * 이벤트별 특화된 헤더 정보 추가
     */
    private void enrichHeadersForEvent(MfaEvent event, FactorContext context, Map<String, Object> headers) {
        switch (event) {
            case FACTOR_SELECTED:
            case FACTOR_SELECTED_OTT:
            case FACTOR_SELECTED_PASSKEY:
                headers.put("selectedFactor", context.getCurrentProcessingFactor());
                headers.put("stepId", context.getCurrentStepId());
                break;

            case OTT_SUBMITTED:
            case PASSKEY_ASSERTION_SUBMITTED:
                headers.put("attemptNumber", context.getRetryCount() + 1);
                break;

            case FACTOR_VERIFICATION_FAILED:
            case OTT_VERIFICATION_FAILED:
            case PASSKEY_VERIFICATION_FAILED:
                headers.put("failureReason", context.getLastError());
                headers.put("remainingAttempts", getMaxRetries() - context.getRetryCount());
                break;

            case SESSION_TIMEOUT:
                headers.put("sessionDuration", calculateSessionDuration(context));
                break;

            default:
                // 기본 헤더만 사용
                break;
        }
    }

    private int getMaxRetries() {
        // TODO: AuthContextProperties에서 가져오기
        return 3;
    }

    private long calculateSessionDuration(FactorContext context) {
        // 세션 시작 시간을 기반으로 계산
        // FactorContext에 getCreatedAt() 메서드가 추가되어야 함
        // 임시로 현재 시간 반환
        return 0L; // TODO: context.getCreatedAt() 구현 후 수정
    }
}