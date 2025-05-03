package io.springsecurity.springsecurity6x.security.core.state.oauth2.client;

public record OAuth2ClientRequest(String clientId, String clientSecret, String scope) {}