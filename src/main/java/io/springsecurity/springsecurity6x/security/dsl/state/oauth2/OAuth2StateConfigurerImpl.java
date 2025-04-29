package io.springsecurity.springsecurity6x.security.dsl.state.oauth2;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.*;
import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.filter.OAuth2AuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.authentication.OAuth2AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.OAuth2TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.OAuth2TokenParser;
import io.springsecurity.springsecurity6x.security.token.service.OAuth2TokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.OAuth2TokenValidator;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * OAuth2 Client 설정을 DSL 방식으로 구성하는 클래스
 */
public class OAuth2StateConfigurerImpl implements OAuth2StateConfigurer {

    private String tokenUri;
    private String clientId;
    private String clientSecret;
    private String scope;

    private AuthenticationHandlers handlers;
    private TokenService tokenService;
    private final TokenTransportStrategy transport;

    public OAuth2StateConfigurerImpl(AuthContextProperties properties) {
        if (properties.getOauth2() == null) {
            throw new IllegalArgumentException("OAuth2 설정이 누락되었습니다. application.yml 파일을 확인하세요.");
        }

        this.tokenUri = properties.getOauth2().getIssuerUri() + properties.getOauth2().getTokenEndpoint();
        this.clientId = properties.getOauth2().getClientId();
        this.clientSecret = properties.getOauth2().getClientSecret();
        this.scope = properties.getOauth2().getScope();

        TokenTransportType transportType = properties.getTokenTransportType();
        this.transport = TokenTransportStrategyFactory.create(transportType);
    }

    public OAuth2StateConfigurerImpl tokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
        return this;
    }

    public OAuth2StateConfigurerImpl clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public OAuth2StateConfigurerImpl clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public OAuth2StateConfigurerImpl scope(String scope) {
        this.scope = scope;
        return this;
    }

    @Override
    public AuthenticationHandlers authHandlers() {
        return handlers;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        OAuth2HttpClient httpClient = new OAuth2HttpClient();
        OAuth2ClientRequest clientRequest = new OAuth2ClientRequest(clientId, clientSecret, scope);
        OAuth2TokenProvider tokenProvider = new OAuth2TokenProvider(tokenUri, clientRequest);
        OAuth2ResourceClient resourceClient = new OAuth2ResourceClient(tokenProvider);

        // --- TokenService 준비
        var creator = new OAuth2TokenCreator(tokenProvider);
        var validator = new OAuth2TokenValidator(resourceClient);
        this.tokenService = new OAuth2TokenService(creator, validator);

        // --- AuthenticationHandlers 준비
        this.handlers = new OAuth2AuthenticationHandlers(tokenService, transport);

        http.setSharedObject(OAuth2HttpClient.class, httpClient);
        http.setSharedObject(OAuth2TokenProvider.class, tokenProvider);
        http.setSharedObject(OAuth2ResourceClient.class, resourceClient);
        http.setSharedObject(TokenService.class, tokenService);
        http.setSharedObject(AuthenticationHandlers.class, handlers);
        http.setSharedObject(TokenTransportStrategy.class, transport);
        http.setSharedObject(LogoutHandler.class, handlers.logoutHandler());
    }

    @Override
    public void configure(HttpSecurity http) {
        OAuth2AuthorizationFilter oauth2Filter = new OAuth2AuthorizationFilter(
                http.getSharedObject(TokenService.class),
                http.getSharedObject(TokenTransportStrategy.class),
                http.getSharedObject(LogoutHandler.class)
        );
        http.addFilterBefore(oauth2Filter, UsernamePasswordAuthenticationFilter.class);
    }
}


