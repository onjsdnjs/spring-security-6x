package io.springsecurity.springsecurity6x.security.core.adapter.state.oauth2.client;

public record OAuth2IntrospectionResponse(boolean active, String username, String scope, Long expiresAt) {}

