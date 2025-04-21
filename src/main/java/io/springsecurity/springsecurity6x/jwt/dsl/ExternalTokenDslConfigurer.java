package io.springsecurity.springsecurity6x.jwt.dsl;

import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.enums.TokenType;
import io.springsecurity.springsecurity6x.jwt.filter.JwtAuthenticationFilter;
import io.springsecurity.springsecurity6x.jwt.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.jwt.filter.JwtLogoutFilter;
import io.springsecurity.springsecurity6x.jwt.filter.JwtRefreshTokenFilter;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import io.springsecurity.springsecurity6x.jwt.tokenservice.ExternalJwtTokenService;
import io.springsecurity.springsecurity6x.jwt.tokenservice.InternalJwtTokenService;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.concurrent.TimeUnit;

public class ExternalTokenDslConfigurer extends AbstractHttpConfigurer<ExternalTokenDslConfigurer, HttpSecurity> {

    private static ApplicationContext applicationContext;

    private final IntegrationAuthProperties properties;
    private TokenService tokenService;
    private RefreshTokenStore refreshTokenStore;
    private String tokenPrefix = "Bearer ";
    private long accessTokenValidity = 3600000;
    private long refreshTokenValidity = 604800000;
    private String loginUri = "/api/auth/login";
    private String logoutUri = "/api/auth/logout";
    private String refreshUri = "/api/auth/refresh";
    private String rolesClaim = "roles";
    private boolean enableRefreshToken = true;
    private AuthenticationManager authenticationManager;

    public ExternalTokenDslConfigurer(IntegrationAuthProperties properties) {
        this.properties = properties;
    }


    @Override
    public void configure(HttpSecurity http) {

        JwtAuthenticationFilter authenticationFilter = new JwtAuthenticationFilter();

        if (authenticationManager != null) {
            authenticationFilter.setAuthenticationManager(authenticationManager);

        }else{
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            authenticationFilter.setAuthenticationManager(authenticationManager);
        }
        if(properties.getTokenType() == TokenType.EXTERNAL){
            tokenService = applicationContext.getBean(ExternalJwtTokenService.class);

        }else if(properties.getTokenType() == TokenType.INTERNAL){
            tokenService = applicationContext.getBean(InternalJwtTokenService.class);
        }
        authenticationFilter.setTokenService(tokenService);
        authenticationFilter.setTokenPrefix(tokenPrefix);
        authenticationFilter.setAccessTokenValidity(accessTokenValidity);
        authenticationFilter.setRefreshTokenValidity(refreshTokenValidity);
        authenticationFilter.setLoginUri(loginUri);
        authenticationFilter.setRolesClaim(rolesClaim);
        authenticationFilter.setEnableRefreshToken(enableRefreshToken);
        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        JwtAuthorizationFilter authorizationFilter = new JwtAuthorizationFilter(tokenService);
        http.addFilterAfter(authorizationFilter, JwtAuthenticationFilter.class);

        JwtRefreshTokenFilter refreshFilter = new JwtRefreshTokenFilter(tokenService,refreshUri);
        http.addFilterAfter(refreshFilter, JwtAuthorizationFilter.class);

        JwtLogoutFilter logoutFilter = new JwtLogoutFilter(tokenService,logoutUri);
        http.addFilterAfter(logoutFilter, JwtRefreshTokenFilter.class);


    }

    public static ExternalTokenDslConfigurer jwt(IntegrationAuthProperties properties, ApplicationContext applicationContext) {
        ExternalTokenDslConfigurer.applicationContext = applicationContext;
        return new ExternalTokenDslConfigurer(properties);
    }

    public ExternalTokenDslConfigurer tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
        return this;
    }

    public ExternalTokenDslConfigurer refreshTokenStore(RefreshTokenStore store) {
        this.refreshTokenStore = store;
        return this;
    }

    public ExternalTokenDslConfigurer loginEndpoint(String uri) {
        this.loginUri = uri;
        return this;
    }

    public ExternalTokenDslConfigurer logoutEndpoint(String uri) {
        this.logoutUri = uri;
        return this;
    }

    public ExternalTokenDslConfigurer refreshEndpoint(String uri) {
        this.refreshUri = uri;
        return this;
    }

    public ExternalTokenDslConfigurer tokenPrefix(String prefix) {
        this.tokenPrefix = prefix;
        return this;
    }

    public ExternalTokenDslConfigurer accessTokenValidity(long time, TimeUnit unit) {
        this.accessTokenValidity = unit.toMillis(time);
        return this;
    }

    public ExternalTokenDslConfigurer refreshTokenValidity(long time, TimeUnit unit) {
        this.refreshTokenValidity = unit.toMillis(time);
        return this;
    }

    public ExternalTokenDslConfigurer rolesClaim(String claim) {
        this.rolesClaim = claim;
        return this;
    }

    public ExternalTokenDslConfigurer enableRefreshToken(boolean enable) {
        this.enableRefreshToken = enable;
        return this;
    }
}

