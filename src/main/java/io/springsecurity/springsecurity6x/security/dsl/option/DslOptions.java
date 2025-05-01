package io.springsecurity.springsecurity6x.security.dsl.option;

import java.util.HashMap;
import java.util.Map;

public abstract class DslOptions {
    protected Map<String, Object> values = new HashMap<>();

    public void set(String key, Object value) {
        values.put(key, value);
    }

    public Map<String, Object> getValues() {
        return values;
    }
}