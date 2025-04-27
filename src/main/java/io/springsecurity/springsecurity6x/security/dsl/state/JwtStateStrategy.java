package io.springsecurity.springsecurity6x.security.dsl.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.dsl.authorizationserver.AuthorizationServerClient;
import io.springsecurity.springsecurity6x.security.dsl.authorizationserver.SpringOAuth2AuthorizationServerClient;
import io.springsecurity.springsecurity6x.security.enums.TokenIssuer;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;

import java.util.Map;

/**
 * JWT 기반 인증 상태 전략
 */
public class JwtStateStrategy implements AuthenticationStateStrategy {
    private TokenService tokenService;
    private TokenTransportHandler tokenTransportHandler = new HeaderTokenTransportHandler();
    private TokenIssuer tokenIssuer = TokenIssuer.INTERNAL; // 기본 INTERNAL
    private boolean tokenIssuerSet = false;
    private final AuthContextProperties properties;
    private AuthorizationServerClient authServerClient; // AUTH_SERVER 연동 객체

    public JwtStateStrategy(ApplicationContext applicationContext){
        this.tokenService = applicationContext.getBean(TokenService.class);
        this.properties = applicationContext.getBean(AuthContextProperties.class);
        this.authServerClient = new SpringOAuth2AuthorizationServerClient(properties);
    }

    public JwtStateStrategy tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
        return this;
    }

    public JwtStateStrategy authorizationServerClient(AuthorizationServerClient client) {
        this.authServerClient = client;
        return this;
    }

    public JwtStateStrategy tokenTransportHandler(TokenTransportHandler tokenTransportHandler) {
        if (tokenTransportHandler == null) {
            throw new IllegalArgumentException("tokenTransportHandler cannot be null");
        }
        this.tokenTransportHandler = tokenTransportHandler;
        return this;
    }

    public JwtStateStrategy tokenIssuer(TokenIssuer issuer) {
        if (issuer == null || tokenIssuerSet) {
            throw new IllegalArgumentException("TokenIssuer cannot be null or can only be set once");
        }
        this.tokenIssuer = issuer;
        this.tokenIssuerSet = true;
        return this;
    }

    public TokenService tokenService() {
        return tokenService;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(ctx -> ctx.securityContextRepository(new NullSecurityContextRepository()))
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint())
                        .accessDeniedHandler(accessDeniedHandler())
                )
                .logout(logout -> logout.addLogoutHandler(logoutHandler()));;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(new JwtAuthorizationFilter(tokenService, tokenTransportHandler, logoutHandler()), ExceptionTranslationFilter.class);
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        if (tokenTransportHandler == null) {
            throw new IllegalStateException("TokenTransportHandler must be configured before use.");
        }

        return (request, response, authentication) -> {
            String accessToken;
            String refreshToken = null;
            if (tokenIssuer == TokenIssuer.INTERNAL) {
                accessToken = tokenService.createAccessToken(builder -> builder
                        .username(authentication.getName())
                        .roles(authentication.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList())
                        .validity(properties.getInternal().getAccessTokenTtl())
                );

                if (properties.getExternal().isEnableRefreshToken()) {
                    refreshToken = tokenService.createRefreshToken(builder -> builder
                            .username(authentication.getName())
                            .roles(authentication.getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .toList())
                            .validity(properties.getInternal().getRefreshTokenTtl())
                    );
                }
            } else if (tokenIssuer == TokenIssuer.AUTHORIZATION_SERVER) {
                if (authServerClient == null) {
                    throw new IllegalStateException("AuthorizationServerClient must be configured when using AUTHORIZATION_SERVER mode");
                }
                accessToken = authServerClient.issueAccessToken();
            } else {
                throw new IllegalStateException("Unknown TokenIssuer");
            }

            tokenTransportHandler.sendAccessToken(response, accessToken);
            if (refreshToken != null) {
                tokenTransportHandler.sendRefreshToken(response, refreshToken);
            }

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            new ObjectMapper().writeValue(response.getWriter(), Map.of("message", "Authentication Successful"));
        };
    }



    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
    }

    @Override
    public AuthenticationEntryPoint entryPoint() {
        return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
    }

    @Override
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, exception) -> response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
    }

    @Override
    public TokenLogoutHandler logoutHandler() {
        return new TokenLogoutHandler(tokenService);
    }
}


