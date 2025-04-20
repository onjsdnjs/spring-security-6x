package io.springsecurity.springsecurity6x.jwt.dsl;

import io.springsecurity.springsecurity6x.jwt.JwtScopeAuthorizationConfigurer;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.filter.JwtAuthenticationFilter;
import io.springsecurity.springsecurity6x.jwt.filter.JwtRefreshTokenFilter;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class JwtSecurityConfigurer extends AbstractHttpConfigurer<JwtSecurityConfigurer, HttpSecurity> {

    private TokenService tokenService;
    private RefreshTokenStore refreshTokenStore;
    private String tokenPrefix = "Bearer ";
    private long accessTokenValidity = 3600000;
    private long refreshTokenValidity = 604800000;
    private String loginUri = "/api/auth/login";
    private String logoutUri = "/api/auth/logout";
    private String refreshUri = "/api/auth/refresh";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";
    private boolean enableRefreshToken = true;
    private Map<String, String> scopeToPattern = new HashMap<>();
    private AuthenticationManager authenticationManager;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;



    @Override
    public void configure(HttpSecurity http) {
        // 로그인 필터 설정
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();

        if (authenticationManager != null) {
            filter.setAuthenticationManager(authenticationManager);
        }else{
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            filter.setAuthenticationManager(authenticationManager);
        }
        filter.setTokenService(tokenService);
        filter.setRefreshTokenStore(refreshTokenStore);
        filter.setTokenPrefix(tokenPrefix);
        filter.setAccessTokenValidity(accessTokenValidity);
        filter.setRefreshTokenValidity(refreshTokenValidity);
        filter.setLoginUri(loginUri);
        filter.setLogoutUri(logoutUri);
        filter.setRefreshUri(refreshUri);
        filter.setRolesClaim(rolesClaim);
        filter.setScopesClaim(scopesClaim);
        filter.setEnableRefreshToken(enableRefreshToken);
        filter.setScopeToPattern(scopeToPattern);
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        // 리프레시 토큰 필터 설정
        JwtRefreshTokenFilter refreshFilter = new JwtRefreshTokenFilter(refreshUri);
        refreshFilter.setTokenService(tokenService);
        refreshFilter.setRefreshTokenStore(refreshTokenStore);
        http.addFilterAfter(refreshFilter, JwtAuthenticationFilter.class);
    }

    public static JwtSecurityConfigurer jwt() {
        return new JwtSecurityConfigurer();
    }

    public JwtSecurityConfigurer tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
        return this;
    }

    public JwtSecurityConfigurer refreshTokenStore(RefreshTokenStore store) {
        this.refreshTokenStore = store;
        return this;
    }

    public JwtSecurityConfigurer loginEndpoint(String uri) {
        this.loginUri = uri;
        return this;
    }

    public JwtSecurityConfigurer logoutEndpoint(String uri) {
        this.logoutUri = uri;
        return this;
    }

    public JwtSecurityConfigurer refreshEndpoint(String uri) {
        this.refreshUri = uri;
        return this;
    }

    public JwtSecurityConfigurer tokenPrefix(String prefix) {
        this.tokenPrefix = prefix;
        return this;
    }

    public JwtSecurityConfigurer accessTokenValidity(long time, TimeUnit unit) {
        this.accessTokenValidity = unit.toMillis(time);
        return this;
    }

    public JwtSecurityConfigurer refreshTokenValidity(long time, TimeUnit unit) {
        this.refreshTokenValidity = unit.toMillis(time);
        return this;
    }

    public JwtSecurityConfigurer rolesClaim(String claim) {
        this.rolesClaim = claim;
        return this;
    }

    public JwtSecurityConfigurer scopesClaim(String claim) {
        this.scopesClaim = claim;
        return this;
    }

    public JwtSecurityConfigurer enableRefreshToken(boolean enable) {
        this.enableRefreshToken = enable;
        return this;
    }

    public JwtSecurityConfigurer authenticationManager(AuthenticationManager manager) {
        this.authenticationManager = manager;
        return this;
    }

    public JwtSecurityConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.successHandler = handler;
        return this;
    }

    public JwtSecurityConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.failureHandler = handler;
        return this;
    }

    public JwtSecurityConfigurer authorizeScopes(Consumer<JwtScopeAuthorizationConfigurer> consumer) {
        JwtScopeAuthorizationConfigurer conf = new JwtScopeAuthorizationConfigurer();
        consumer.accept(conf);
        this.scopeToPattern = conf.getScopeToPattern();
        return this;
    }
}

