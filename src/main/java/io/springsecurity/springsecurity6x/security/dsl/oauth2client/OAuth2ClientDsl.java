package io.springsecurity.springsecurity6x.security.dsl.oauth2client;

import io.springsecurity.springsecurity6x.security.dsl.oauth2client.client.OAuth2ClientRequest;
import io.springsecurity.springsecurity6x.security.dsl.oauth2client.client.OAuth2ResourceClient;
import io.springsecurity.springsecurity6x.security.dsl.oauth2client.client.OAuth2TokenProvider;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;

/**
 * OAuth2 Client 설정을 DSL 방식으로 구성하는 클래스
 */
public class OAuth2ClientDsl {

    private String tokenUri;
    private String clientId;
    private String clientSecret;
    private String scope;
    private final AuthContextProperties properties;

    private OAuth2TokenProvider tokenProvider;
    private OAuth2ResourceClient resourceClient;

    public OAuth2ClientDsl(AuthContextProperties properties) {
        this.properties = properties;
        this.tokenUri = properties.getExternal().getIssuerUri() + properties.getExternal().getTokenEndpoint();
        this.clientId = properties.getExternal().getClientId();
        this.clientSecret = properties.getExternal().getClientSecret();
        this.scope = properties.getExternal().getScope();
    }

    public OAuth2ClientDsl build() {
        if (tokenUri == null || clientId == null || clientSecret == null || scope == null) {
            throw new IllegalStateException("OAuth2ClientDsl 설정이 완전하지 않습니다.");
        }
        OAuth2ClientRequest clientRequest = new OAuth2ClientRequest(clientId, clientSecret, scope);
        this.tokenProvider = new OAuth2TokenProvider(tokenUri, clientRequest);
        this.resourceClient = new OAuth2ResourceClient(tokenProvider);
        return this;
    }

    public OAuth2ResourceClient resourceClient() {
        if (resourceClient == null) {
            throw new IllegalStateException("build() 호출 후 사용해야 합니다.");
        }
        return resourceClient;
    }

    public OAuth2ClientDsl tokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
        return this;
    }

    public OAuth2ClientDsl clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public OAuth2ClientDsl clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public OAuth2ClientDsl scope(String scope) {
        this.scope = scope;
        return this;
    }
}

