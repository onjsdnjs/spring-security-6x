package io.springsecurity.springsecurity6x.security.core.adapter.state.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.adapter.StateAdapter;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.utils.writer.JsonAuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Objects;

/**
 * JWT 기반 상태 관리 기능을 HttpSecurity에 적용하는 StateFeature 구현체입니다.
 * IdentityStateDsl의 jwt() 메소드에서 사용됩니다.
 */
@Slf4j
public final class JwtStateAdapter implements StateAdapter { // final class

    private static final String ID = "jwt"; // 상수로 변경

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx) throws Exception {
        Objects.requireNonNull(http, "HttpSecurity cannot be null for JwtStateFeature.apply");
        Objects.requireNonNull(platformCtx, "PlatformContext cannot be null for JwtStateFeature.apply");
        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");

        log.debug("JwtStateFeature [{}]: Applying to HttpSecurity (hash: {}).", getId(), http.hashCode());

        TokenService tokenService;
        JwtLogoutHandler jwtLogoutHandler;
        ObjectMapper objectMapper;
        LogoutSuccessHandler jwtLogoutSuccessHandler;
        try {
            tokenService = appContext.getBean(TokenService.class);
            jwtLogoutHandler = appContext.getBean(JwtLogoutHandler.class);
            objectMapper = appContext.getBean(ObjectMapper.class);
            JsonAuthResponseWriter jsonAuthResponseWriter = appContext.getBean(JsonAuthResponseWriter.class);

            jwtLogoutSuccessHandler = new JwtLogoutSuccessHandler(objectMapper);

            http.setSharedObject(TokenService.class, tokenService);
            http.setSharedObject(LogoutHandler.class, jwtLogoutHandler);
            http.setSharedObject(LogoutSuccessHandler.class, jwtLogoutSuccessHandler);
            http.setSharedObject(ObjectMapper.class, objectMapper);
            http.setSharedObject(JsonAuthResponseWriter.class, jsonAuthResponseWriter);


        } catch (NoSuchBeanDefinitionException e) {
            log.error("JwtStateFeature [{}]: Required bean ({}) not found in ApplicationContext. JWT State will not be fully configured.",
                    getId(), e.getMessage(), e);
            throw new IllegalStateException("Required bean for JWT state configuration not found: " + e.getMessage(), e);
        }

        http
//                .csrf(AbstractHttpConfigurer::disable) // JWT는 일반적으로 CSRF 보호가 필요 없음 (Stateless)
//                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // JWT는 Stateless
                // 기본 exceptionHandling은 ASEP 또는 플랫폼 전역 설정에 맡길 수 있음.
                // 필요하다면 여기서 JWT에 특화된 기본 AuthenticationEntryPoint/AccessDeniedHandler 설정 가능.
                // .exceptionHandling(e -> e
                //         .authenticationEntryPoint((req, res, ex) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: JWT Authentication Required"))
                //         .accessDeniedHandler((req, res, ex) -> res.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: Insufficient JWT Permissions")))
                .logout(logout -> logout // JWT 로그아웃 설정
                        .logoutRequestMatcher(new AntPathRequestMatcher("/api/auth/logout")) // 플랫폼 기본 로그아웃 URL
                        .addLogoutHandler(jwtLogoutHandler) // 커스텀 JWT 로그아웃 핸들러
                        .logoutSuccessHandler(jwtLogoutSuccessHandler) // 커스텀 JWT 로그아웃 성공 핸들러
                        .invalidateHttpSession(false) // JWT는 세션을 사용하지 않으므로 false (또는 true로 두고 세션 정리)
                        .clearAuthentication(true)    // SecurityContext에서 Authentication 객체 제거
                );

        JwtStateConfigurer jwtStateConfigurer = new JwtStateConfigurer();
        http.with(jwtStateConfigurer, Customizer.withDefaults()); // 또는 사용자가 제공한 Customizer 사용

        log.info("JwtStateFeature [{}]: Applied JWT state configurations (CSRF disabled, Stateless session, Logout handler, JwtStateConfigurer) to HttpSecurity.", getId());
    }
}