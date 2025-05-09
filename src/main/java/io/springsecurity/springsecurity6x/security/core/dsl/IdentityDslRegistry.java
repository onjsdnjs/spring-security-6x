package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.RestDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class IdentityDslRegistry extends AbstractFlowRegistrar {

    public IdentityDslRegistry() {
        super(PlatformConfig.builder());
    }

    @Override
    public SecurityPlatformDsl global(SafeHttpCustomizer customizer) {
        platformBuilder.global(wrapSafe(customizer));
        return this;
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                System.err.println("글로벌 커스터마이저 예외: " + e.getMessage());
            }
        };
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) {
        return registerFlow(AuthType.FORM, customizer, FormDslConfigurerImpl::new);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) {
        return registerFlow(AuthType.REST, customizer, RestDslConfigurerImpl::new);
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
