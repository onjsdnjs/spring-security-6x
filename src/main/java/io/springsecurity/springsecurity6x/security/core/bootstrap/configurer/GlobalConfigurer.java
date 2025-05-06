package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 글로벌 HTTP 보안 설정을 적용합니다.
 */
public class GlobalConfigurer implements SecurityConfigurer {
    @Override
    public void init(PlatformContext ctx, PlatformConfig cfg) {
        Customizer<HttpSecurity> customizer = cfg.getGlobal();
        if (customizer != null) {
            customizer.customize(ctx.getHttp());
        }
    }
}
