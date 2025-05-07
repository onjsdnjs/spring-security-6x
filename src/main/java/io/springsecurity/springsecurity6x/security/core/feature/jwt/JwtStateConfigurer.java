package io.springsecurity.springsecurity6x.security.core.feature.jwt;

import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtPreAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.authentication.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.logout.StrategyAwareLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.JwtRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;

/**
 * JWT 상태 전략을 HttpSecurity에 적용하는 설정자
 */
public class JwtStateConfigurer extends AbstractHttpConfigurer<JwtStateConfigurer, HttpSecurity> {

    private final SecretKey key;
    private final AuthContextProperties props;
    private final TokenTransportStrategy transport;

    public JwtStateConfigurer(SecretKey key,
                              AuthContextProperties props,
                              TokenTransportStrategy transport) {
        this.key = key;
        this.props = props;
        this.transport = transport;
    }

    /** JWT에 필요한 공통 HTTP 설정 (CSRF, 세션 관리, 예외 처리 등) */
    @Override
    public void init(HttpSecurity http) throws Exception {
        if (props.getTokenTransportType() == TokenTransportType.HEADER) {
            http.csrf(AbstractHttpConfigurer::disable);
        } else {
            http.csrf(csrf -> csrf
                    .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")));
        }
        http
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) ->
                                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
                        .accessDeniedHandler((req, res, ex) ->
                                res.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")));
    }

    /** JWT 인증 필터, 리프레시 토큰 필터 등을 HttpSecurity에 추가 */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        // 파서·토큰 생성기·저장소·서비스·핸들러 생성
        TokenParser parser = new JwtTokenParser(key);
        JwtTokenCreator creator = new JwtTokenCreator(key);
        RefreshTokenStore store = new JwtRefreshTokenStore(parser, props);
        TokenValidator validator = new JwtTokenValidator(parser, store, props.getRefreshRotateThreshold());
        TokenService service = new JwtTokenService(
                validator, creator, store, transport, props);
        transport.setTokenService(service);
        AuthenticationHandlers handlers = new JwtAuthenticationHandlers(service);

        // 로그아웃 설정
        http.logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .addLogoutHandler(handlers.logoutHandler())
                .logoutSuccessHandler(new StrategyAwareLogoutSuccessHandler()));

        // 필터 체인: 권한 검사, 리프레시, 사전 인증 순서
        http.addFilterAfter(new JwtAuthorizationFilter(service, handlers.logoutHandler()), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(service, handlers.logoutHandler()), JwtAuthorizationFilter.class);
        http.addFilterBefore(new JwtPreAuthenticationFilter(service), LogoutFilter.class);
    }
}

