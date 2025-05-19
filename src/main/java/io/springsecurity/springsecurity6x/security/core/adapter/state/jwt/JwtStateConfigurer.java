package io.springsecurity.springsecurity6x.security.core.adapter.state.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtPreAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.http.JsonAuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Objects;

/**
 * JWT 기반 상태 관리 전략을 HttpSecurity에 적용하는 설정자입니다.
 * JWT 관련 인증/인가 필터들을 필터 체인에 등록합니다.
 */
@Slf4j
public final class JwtStateConfigurer extends AbstractHttpConfigurer<JwtStateConfigurer, HttpSecurity> { // final class

    public JwtStateConfigurer() {
        log.debug("JwtStateConfigurer instance created.");
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        if (context == null) {
            log.warn("JwtStateConfigurer: ApplicationContext not found in HttpSecurity sharedObjects during init. " +
                    "Dependencies will be resolved in configure phase.");
        }
        log.debug("JwtStateConfigurer initializing for HttpSecurity (hash: {}).", http.hashCode());
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        log.debug("JwtStateConfigurer configuring HttpSecurity (hash: {}). Adding JWT filters.", http.hashCode());

        TokenService tokenService = http.getSharedObject(TokenService.class);
        LogoutHandler jwtLogoutHandler = http.getSharedObject(LogoutHandler.class);
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        JsonAuthResponseWriter responseWriter;

        if (context != null) {
            try {
                responseWriter = context.getBean(JsonAuthResponseWriter.class);
            } catch (NoSuchBeanDefinitionException e) {
                log.warn("JwtStateConfigurer: ObjectMapper bean not found in ApplicationContext either. Using new ObjectMapper() for JsonAuthResponseWriter.");
                responseWriter = new JsonAuthResponseWriter(new ObjectMapper());
            }
        } else {
            responseWriter = new JsonAuthResponseWriter(new ObjectMapper()); // ApplicationContext도 없다면 기본 생성
        }

        Objects.requireNonNull(tokenService, "TokenService not found in HttpSecurity sharedObjects. It must be set by JwtStateFeature.");
        Objects.requireNonNull(jwtLogoutHandler, "LogoutHandler (for JWT) not found in HttpSecurity sharedObjects. It must be set by JwtStateFeature.");

        // 1. JwtPreAuthenticationFilter: 요청 헤더에서 토큰을 미리 검증하고 SecurityContext에 임시 저장 (선택적 필터)
        JwtPreAuthenticationFilter preAuthFilter = new JwtPreAuthenticationFilter(tokenService);
        http.addFilterBefore(postProcess(preAuthFilter), LogoutFilter.class);
        log.debug("JwtStateConfigurer: Added JwtPreAuthenticationFilter before LogoutFilter.");

        // 2. JwtAuthorizationFilter: SecurityContext에 저장된 인증 정보 또는 요청 헤더의 토큰을 기반으로 최종 인가 결정
        // (ExceptionTranslationFilter는 인증/인가 예외를 처리하므로, 그 전에 실제 인가 필터가 와야 함)
        JwtAuthorizationFilter authorizationFilter = new JwtAuthorizationFilter(tokenService, jwtLogoutHandler);
        http.addFilterAfter(postProcess(authorizationFilter), ExceptionTranslationFilter.class);
        log.debug("JwtStateConfigurer: Added JwtAuthorizationFilter after ExceptionTranslationFilter.");


        // 3. JwtRefreshAuthenticationFilter: Access Token 만료 시 Refresh Token을 사용하여 새로운 토큰을 발급 시도
        // (JwtAuthorizationFilter 이후에 위치하여, Access Token 검증 실패 후 Refresh 시도)
        JwtRefreshAuthenticationFilter refreshFilter = new JwtRefreshAuthenticationFilter(tokenService, jwtLogoutHandler, responseWriter);
        http.addFilterAfter(postProcess(refreshFilter), JwtAuthorizationFilter.class);
        log.debug("JwtStateConfigurer: Added JwtRefreshAuthenticationFilter after JwtAuthorizationFilter.");

        log.info("JwtStateConfigurer: JWT filters (PreAuth, Authorization, Refresh) configured for HttpSecurity (hash: {}).", http.hashCode());
    }
}

