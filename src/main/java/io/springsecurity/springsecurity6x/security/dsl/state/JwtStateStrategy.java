package io.springsecurity.springsecurity6x.security.dsl.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.enums.TokenTransport;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.utils.CookieUtil;
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

import java.util.List;
import java.util.Map;

/**
 * JWT 기반 인증 상태 전략
 */
public class JwtStateStrategy implements AuthenticationStateStrategy {
    private final ApplicationContext applicationContext;
    private TokenService tokenService;
    private final TokenTransportHandler tokenTransportHandler = new HeaderTokenTransportHandler();
    private final AuthContextProperties properties;

    public JwtStateStrategy(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        properties = this.applicationContext.getBean(AuthContextProperties.class);
    }

    public JwtStateStrategy tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
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
        // 모든 요청에 대해 JWT 토큰을 검증하는 필터 등록
        http.addFilterAfter(new JwtAuthorizationFilter(tokenService, tokenTransportHandler, logoutHandler()), ExceptionTranslationFilter.class);
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {

        return (request, response, authentication) -> {
            if (tokenTransportHandler == null) {
                throw new IllegalStateException("TokenTransportHandler must be configured before use.");
            }

            String username = authentication.getName();
            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String accessToken = tokenService.createAccessToken(builder -> builder
                    .username(username)
                    .roles(roles)
                    .validity(properties.getInternal().getAccessTokenTtl())
            );

            String refreshToken = properties.getExternal().isEnableRefreshToken() ?
                    tokenService.createRefreshToken(builder -> builder
                            .username(username)
                            .roles(roles)
                            .validity(properties.getInternal().getRefreshTokenTtl())
                    ) : null;

            tokenTransportHandler.sendAccessToken(response, accessToken);
            if (refreshToken != null) {
                tokenTransportHandler.sendRefreshToken(response, refreshToken);
            }

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            new ObjectMapper().writeValue(response.getWriter(), Map.of("message", "JWT Authentication Successful"));
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


