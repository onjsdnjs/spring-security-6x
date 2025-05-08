package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.internal;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.handler.logout.StrategyAwareLogoutSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Slf4j
public class DefaultLogoutConfigurer implements SecurityConfigurer {
    private final LogoutHandler defaultLogoutHandler;

    public DefaultLogoutConfigurer(LogoutHandler defaultLogoutHandler) {
        this.defaultLogoutHandler = defaultLogoutHandler;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // Global init 단계에 아무 작업 안 함
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        fc.http().logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/api/auth/logout"))
                .addLogoutHandler(defaultLogoutHandler)
                .logoutSuccessHandler(new StrategyAwareLogoutSuccessHandler())
        );
    }

    @Override
    public int getOrder() {
        // 내부 설정이니까 매우 높은 우선순위(낮은 숫자)
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}

