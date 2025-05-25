package io.springsecurity.springsecurity6x.security.statemachine.core.event;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaDeadLetterQueue {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final String DLQ_KEY_PREFIX = "mfa:dlq:";

    @Async("mfaEventExecutor")
    public void sendToDeadLetter(String sessionId, MfaEvent event, Exception error,
                                 Object context) {
        try {
            String dlqId = UUID.randomUUID().toString();
            String key = DLQ_KEY_PREFIX + dlqId;

            Map<String, Object> dlqEntry = new HashMap<>();
            dlqEntry.put("id", dlqId);
            dlqEntry.put("sessionId", sessionId);
            dlqEntry.put("event", event != null ? event.name() : "UNKNOWN");
            dlqEntry.put("errorType", error.getClass().getName());
            dlqEntry.put("errorMessage", error.getMessage());
            dlqEntry.put("timestamp", LocalDateTime.now().toString());
            dlqEntry.put("context", context);

            // Redis에 저장 (7일 TTL)
            redisTemplate.opsForValue().set(key, dlqEntry, 7, TimeUnit.DAYS);

            log.error("Event sent to DLQ: sessionId={}, event={}, error={}",
                    sessionId, event, error.getMessage());

            // 알림 전송
            notifyAdministrators(dlqEntry);

        } catch (Exception e) {
            log.error("Failed to send to DLQ", e);
        }
    }

    private void notifyAdministrators(Map<String, Object> dlqEntry) {
        // 관리자 알림 로직 구현
        // 예: 이메일, Slack 등
    }
}
