package io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client;

public class OAuth2IntrospectionResponse {

    private final boolean active;
    private final String username;
    private final String scope;
    private final Long expiresAt;

    public OAuth2IntrospectionResponse(boolean active, String username, String scope, Long expiresAt) {
        this.active = active;
        this.username = username;
        this.scope = scope;
        this.expiresAt = expiresAt;
    }

    public boolean isActive() {
        return active;
    }

    public String getUsername() {
        return username;
    }

    public String getScope() {
        return scope;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }
}

