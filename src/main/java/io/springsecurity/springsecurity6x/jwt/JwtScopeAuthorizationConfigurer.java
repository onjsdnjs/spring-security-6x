package io.springsecurity.springsecurity6x.jwt;

import java.util.HashMap;
import java.util.Map;

public class JwtScopeAuthorizationConfigurer {

    private final Map<String, String> scopeToPattern = new HashMap<>();

    public JwtScopeAuthorizationConfigurer require(String scope, String pattern) {
        scopeToPattern.put(scope, pattern);
        return this;
    }

    public Map<String, String> getScopeToPattern() {
        return scopeToPattern;
    }
}
