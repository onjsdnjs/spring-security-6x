package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 글로벌 HTTP 보안 설정을 적용합니다.
 */
@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {

    @Override
    public void configure(FlowContext ctx) throws Exception {
        Customizer<HttpSecurity> customizer = ctx.config().global();
        if (customizer != null) {
            try {
                customizer.customize(ctx.http());
            } catch (Exception ex) {
                log.warn("Global customizer failed for flow: {}", ctx.flow().typeName(), ex);
            }
        }
    }
}
