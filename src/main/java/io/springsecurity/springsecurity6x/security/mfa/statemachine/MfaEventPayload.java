package io.springsecurity.springsecurity6x.security.mfa.statemachine;

import lombok.Getter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Getter
public class MfaEventPayload {
    private final Map<String, Object> data;

    private MfaEventPayload(Map<String, Object> data) {
        this.data = Collections.unmodifiableMap(new HashMap<>(data));
    }

    public static MfaEventPayload empty() {
        return new MfaEventPayload(Collections.emptyMap());
    }

    public static MfaEventPayload with(String key, Object value) {
        return new MfaEventPayload(Collections.singletonMap(key, value));
    }

    public static MfaEventPayload withMap(Map<String, Object> data) {
        return new MfaEventPayload(data);
    }

    public <T> T get(String key, Class<T> type) {
        Object value = data.get(key);
        if (value != null && type.isAssignableFrom(value.getClass())) {
            return (T) value;
        }
        return null;
    }

    public Object get(String key) {
        return data.get(key);
    }
}