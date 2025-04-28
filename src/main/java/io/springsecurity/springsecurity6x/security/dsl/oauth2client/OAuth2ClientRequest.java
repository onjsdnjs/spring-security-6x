package io.springsecurity.springsecurity6x.security.dsl.oauth2client;

public record OAuth2ClientRequest(String clientId, String clientSecret, String scope) {}