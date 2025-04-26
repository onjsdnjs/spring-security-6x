package io.springsecurity.springsecurity6x.security.dsl.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.utils.CookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.context.NullSecurityContextRepository;

import java.util.List;
import java.util.Map;

/**
 * JWT 기반 인증 상태 전략
 */
public class JwtStateStrategy implements AuthenticationStateStrategy {
    private final TokenService tokenService;
    public static String TOKEN_PREFIX = "Bearer ";
    public static long ACCESS_TOKEN_VALIDITY = 3600000;     // default: 1 hour
    public static long REFRESH_TOKEN_VALIDITY = 604800000;  // default: 7 days
    private boolean enableRefreshToken = true;

    public JwtStateStrategy(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    // 설정 수정용 메서드 제공
    public JwtStateStrategy tokenPrefix(String prefix) {
        TOKEN_PREFIX = prefix;
        return this;
    }

    public JwtStateStrategy accessTokenValidity(long millis) {
        ACCESS_TOKEN_VALIDITY = millis;
        return this;
    }

    public JwtStateStrategy refreshTokenValidity(long millis) {
        REFRESH_TOKEN_VALIDITY = millis;
        return this;
    }

    public JwtStateStrategy enableRefreshToken(boolean enable) {
        this.enableRefreshToken = enable;
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.securityContext(sc -> sc.securityContextRepository(new NullSecurityContextRepository()));
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint())
                        .accessDeniedHandler(accessDeniedHandler())
                )
                .logout(logout -> logout.addLogoutHandler(logoutHandler()));
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {

        return (request, response, authentication) -> {
            String username = authentication.getName();
            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String accessToken = tokenService.createAccessToken(builder -> builder
                    .username(username)
                    .roles(roles)
                    .validity(3600_000)
            );

            String refreshToken = enableRefreshToken ? tokenService.createRefreshToken(builder -> builder
                    .username(username)
                    .roles(roles)
                    .validity(604800_000)
            ):null;

            CookieUtil.addTokenCookie(request, response, "accessToken", accessToken);
            CookieUtil.addTokenCookie(request, response, "refreshToken", refreshToken);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            new ObjectMapper().writeValue(response.getWriter(), Map.of("message", "JWT 인증 성공"));
        };
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증 실패");
    }

    @Override
    public AuthenticationEntryPoint entryPoint() {
        return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
    }

    @Override
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, exception) -> response.sendError(HttpServletResponse.SC_FORBIDDEN, "접근 거부");
    }

    @Override
    public LogoutHandler logoutHandler() {
        return new TokenLogoutHandler(tokenService);
    }
}


