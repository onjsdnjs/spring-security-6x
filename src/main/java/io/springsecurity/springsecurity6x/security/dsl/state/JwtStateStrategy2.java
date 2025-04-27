/*
package io.springsecurity.springsecurity6x.security.dsl.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.enums.TokenIssuer;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.ExternalJwtCreator;
import io.springsecurity.springsecurity6x.security.token.creator.InternalJwtCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.ExternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.InternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.store.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.validator.DefaultJwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
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

import javax.crypto.SecretKey;
import java.util.List;
import java.util.Map;

public class JwtStateStrategy2 implements AuthenticationStateStrategy {

    private final ApplicationContext applicationContext;
    private TokenIssuer tokenIssuerOverride;
    private TokenTransportHandler tokenTransportHandler = new HeaderTokenTransportHandler();
    private final SecretKey secretKey;
    private final AuthContextProperties properties;

    public JwtStateStrategy2(ApplicationContext applicationContext, AuthContextProperties properties) {
        this.applicationContext = applicationContext;
        this.secretKey = applicationContext.getBean(SecretKey.class);
        this.properties = properties;
    }

    public JwtStateStrategy2 tokenIssuer(TokenIssuer tokenIssuer) {
        if (this.tokenIssuerOverride != null) {
            throw new IllegalStateException("TokenIssuer는 한 번만 설정할 수 있습니다.");
        }
        if (tokenIssuer == null) {
            throw new IllegalArgumentException("TokenIssuer는 null일 수 없습니다.");
        }
        this.tokenIssuerOverride = tokenIssuer;
        return this;
    }

    public JwtStateStrategy2 tokenTransportHandler(TokenTransportHandler handler) {
        if (handler == null) {
            throw new IllegalArgumentException("TokenTransportHandler cannot be null");
        }
        this.tokenTransportHandler = handler;
        return this;
    }

    private TokenIssuer effectiveIssuer() {
        AuthContextProperties properties = applicationContext.getBean(AuthContextProperties.class);
        return tokenIssuerOverride != null ? tokenIssuerOverride : properties.getTokenIssuer();
    }

   private TokenCreator resolveTokenCreator() {
        if (effectiveIssuer() == TokenIssuer.INTERNAL) {
            return new InternalJwtCreator(secretKey);

        } else if (effectiveIssuer() == TokenIssuer.AUTHORIZATION_SERVER) {
            return new ExternalJwtCreator();
        }
        throw new IllegalStateException("지원하지 않는 TokenIssuer: " + effectiveIssuer());
    }

    private TokenValidator resolveTokenValidator() {

        JwtParser parser = null;
        if (effectiveIssuer() == TokenIssuer.INTERNAL) {
            parser = new InternalJwtParser(secretKey);

        } else if (effectiveIssuer() == TokenIssuer.AUTHORIZATION_SERVER) {
            parser = new ExternalJwtParser();
        }

        RefreshTokenStore store = new InMemoryRefreshTokenStore(parser);
        return new DefaultJwtTokenValidator(parser, store, properties.getInternal().getRefreshRotateThreshold());
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
                .logout(logout -> logout.addLogoutHandler(logoutHandler()));
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        TokenValidator validator = resolveTokenValidator();
        http.addFilterAfter(
                new JwtAuthorizationFilter(validator, tokenTransportHandler, logoutHandler()), ExceptionTranslationFilter.class);
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        TokenCreator creator = resolveTokenCreator();
        AuthContextProperties properties = applicationContext.getBean(AuthContextProperties.class);

        return (request, response, authentication) -> {
            String username = authentication.getName();
            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String accessToken = creator.builder()
                    .tokenType("access")
                    .username(username)
                    .roles(roles)
                    .validity(properties.getInternal().getAccessTokenValidity())
                    .build();

            String refreshToken = null;
            if (properties.getInternal().isEnableRefreshToken()) {
                refreshToken = creator.builder()
                        .tokenType("refresh")
                        .username(username)
                        .roles(roles)
                        .validity(properties.getInternal().getRefreshTokenValidity())
                        .build();
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
        return new TokenLogoutHandler(null); // 주입된 TokenService가 따로 필요한 경우 수정
    }
}




*/
