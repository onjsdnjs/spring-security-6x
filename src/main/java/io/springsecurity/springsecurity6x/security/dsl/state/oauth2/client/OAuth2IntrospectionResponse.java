package io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client;

public record OAuth2IntrospectionResponse(boolean active, String username, String scope, Long expiresAt) {}

