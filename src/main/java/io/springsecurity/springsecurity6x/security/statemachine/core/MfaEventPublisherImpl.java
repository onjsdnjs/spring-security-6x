package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * MFA 이벤트 발행자 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaEventPublisherImpl implements MfaEventPublisher {

    private final ApplicationEventPublisher springEventPublisher;
    private final Map<MfaEvent, List<MfaEventListener>> listeners = new ConcurrentHashMap<>();

    @Override
    public void publishEvent(MfaEvent event, FactorContext context, String sessionId) {
        log.debug("Publishing MFA event: {} for session: {}", event, sessionId);

        // 내부 리스너들에게 전파
        List<MfaEventListener> eventListeners = listeners.get(event);
        if (eventListeners != null) {
            for (MfaEventListener listener : eventListeners) {
                try {
                    listener.onEvent(event, context, sessionId);
                } catch (Exception e) {
                    log.error("Error in event listener for event {}: {}", event, e.getMessage(), e);
                }
            }
        }

        // Spring 이벤트로도 발행
        MfaStateChangeEvent springEvent = new MfaStateChangeEvent(this, event, context, sessionId);
        springEventPublisher.publishEvent(springEvent);

        log.info("MFA event {} published for session {}", event, sessionId);
    }

    @Override
    public void subscribe(MfaEvent eventType, MfaEventListener listener) {
        listeners.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>()).add(listener);
        log.debug("Listener subscribed to event type: {}", eventType);
    }

    @Override
    public void unsubscribe(MfaEvent eventType, MfaEventListener listener) {
        List<MfaEventListener> eventListeners = listeners.get(eventType);
        if (eventListeners != null) {
            eventListeners.remove(listener);
            log.debug("Listener unsubscribed from event type: {}", eventType);
        }
    }

    /**
     * Spring 이벤트 객체
     */
    public static class MfaStateChangeEvent extends org.springframework.context.ApplicationEvent {
        private final MfaEvent mfaEvent;
        private final FactorContext context;
        private final String sessionId;

        public MfaStateChangeEvent(Object source, MfaEvent mfaEvent, FactorContext context, String sessionId) {
            super(source);
            this.mfaEvent = mfaEvent;
            this.context = context;
            this.sessionId = sessionId;
        }

        public MfaEvent getMfaEvent() { return mfaEvent; }
        public FactorContext getContext() { return context; }
        public String getSessionId() { return sessionId; }
    }
}