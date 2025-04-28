package io.springsecurity.springsecurity6x.security.dsl.state.oauth2;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ClientRequest;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2HttpClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2TokenProvider;
import io.springsecurity.springsecurity6x.security.filter.OAuth2AuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.DefaultAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.OAuth2AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * OAuth2 Client 설정을 DSL 방식으로 구성하는 클래스
 */
public class OAuth2StateConfigurer extends JwtStateConfigurer {

    private String tokenUri;
    private String clientId;
    private String clientSecret;
    private String scope;
    private AuthenticationHandlers handlers;

    public OAuth2StateConfigurer(AuthContextProperties properties) {

        super(null, properties);
        if (properties == null || properties.getOauth2() == null) {
            throw new IllegalArgumentException("OAuth2 설정이 누락되었습니다. application.yml 파일을 확인하세요.");
        }

        this.tokenUri = properties.getOauth2().getIssuerUri() + properties.getOauth2().getTokenEndpoint();
        this.clientId = properties.getOauth2().getClientId();
        this.clientSecret = properties.getOauth2().getClientSecret();
        this.scope = properties.getOauth2().getScope();
    }

    public OAuth2StateConfigurer tokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
        return this;
    }

    public OAuth2StateConfigurer clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public OAuth2StateConfigurer clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public OAuth2StateConfigurer scope(String scope) {
        this.scope = scope;
        return this;
    }

    public AuthenticationHandlers authHandlers() {
        return handlers;
    }

    @Override
    public void init(HttpSecurity http) {
        OAuth2HttpClient httpClient = new OAuth2HttpClient();
        OAuth2ClientRequest clientRequest = new OAuth2ClientRequest(clientId, clientSecret, scope);
        OAuth2TokenProvider tokenProvider = new OAuth2TokenProvider(tokenUri, clientRequest);
        OAuth2ResourceClient resourceClient = new OAuth2ResourceClient(tokenProvider);

        TokenTransportStrategy transport = new HeaderTokenStrategy();
        this.handlers = new OAuth2AuthenticationHandlers(resourceClient, transport);

        // Spring Security Context에 필요한 컴포넌트 등록
        http.setSharedObject(OAuth2HttpClient.class, httpClient);
        http.setSharedObject(OAuth2TokenProvider.class, tokenProvider);
        http.setSharedObject(OAuth2ResourceClient.class, resourceClient);
        http.setSharedObject(AuthenticationHandlers.class, handlers);
    }

    @Override
    public void configure(HttpSecurity http) {
        OAuth2AuthenticationFilter oauth2Filter = new OAuth2AuthenticationFilter(
                http.getSharedObject(OAuth2HttpClient.class),
                http.getSharedObject(OAuth2TokenProvider.class),
                http.getSharedObject(OAuth2ResourceClient.class)
        );
        http.addFilterBefore(oauth2Filter, UsernamePasswordAuthenticationFilter.class);
    }
}

