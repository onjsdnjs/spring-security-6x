package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.function.Consumer;

/**
 * 각 인증 흐름(Flow) 레벨의 Customizer를 적용합니다.
 */
public class FlowConfigurer implements SecurityConfigurer {
    @Override
    public void init(PlatformContext ctx, PlatformConfig config) { }

    @Override
    public void configure(FlowContext ctx) {
        Customizer<HttpSecurity> flowCustomizer = ctx.flow().getRawHttpCustomizer();
        if (flowCustomizer == null) {
            return;
        }
        flowCustomizer.customize(ctx.http());
    }

    @Override
    public int getOrder() { return 100; }
}

