package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.function.Consumer;

/**
 * 글로벌 HTTP 보안 설정을 적용합니다.
 */
@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {
    @Override
    public void init(PlatformContext ctx, PlatformConfig cfg) {
        Customizer<HttpSecurity> customizer = cfg.global();
        if (customizer != null) {
            try {
                customizer.customize(ctx.http());
            } catch (Exception ex) {
                log.warn("Global customizer failed, ignored", ex);
            }
        }
    }
}
