package io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client;

public record OAuth2ClientRequest(String clientId, String clientSecret, String scope) {}