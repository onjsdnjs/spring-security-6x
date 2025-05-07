package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.function.Consumer;

/**
 * 각 인증 흐름(Flow) 레벨의 Customizer를 적용합니다.
 */
public class FlowConfigurer implements SecurityConfigurer {

    @Override
    public void configure(FlowContext ctx) {
        Consumer<HttpSecurity> flowCustomizer = ctx.flow().customizer();
        if (flowCustomizer != null) {
            flowCustomizer.accept(ctx.http());
        }
    }
}
