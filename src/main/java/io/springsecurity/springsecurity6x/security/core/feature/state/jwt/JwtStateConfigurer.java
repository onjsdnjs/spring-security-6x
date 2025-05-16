package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtPreAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.http.JsonAuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * JWT 상태 전략을 HttpSecurity에 적용하는 설정자
 */
public class JwtStateConfigurer extends AbstractHttpConfigurer<JwtStateConfigurer, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        TokenService service = http.getSharedObject(TokenService.class);
        LogoutHandler logoutHandler = http.getSharedObject(LogoutHandler.class);
        ObjectMapper objectMapper = http.getSharedObject(ObjectMapper.class);

        http.addFilterBefore(new JwtPreAuthenticationFilter(service), LogoutFilter.class);
        http.addFilterAfter(new JwtAuthorizationFilter(service, logoutHandler), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(service, logoutHandler, new JsonAuthResponseWriter(objectMapper)), JwtAuthorizationFilter.class);
    }
}

