package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.OttDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.PasskeyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@Slf4j
public class IdentityDslRegistry extends AbstractFlowRegistrar {

    public IdentityDslRegistry() {
        super(PlatformConfig.builder());
    }

    @Override
    public SecurityPlatformDsl global(SafeHttpCustomizer customizer) {
        platformBuilder.global(wrapSafeGlobalCustomizer(customizer));
        return this;
    }

    private Customizer<HttpSecurity> wrapSafeGlobalCustomizer(SafeHttpCustomizer safeCustomizer) {
        return http -> {
            try {
                safeCustomizer.customize(http);
            } catch (Exception e) {
                String errorMessage = String.format("Error during global HttpSecurity customization: %s", e.getMessage());
                log.error(errorMessage, e);
                throw new DslConfigurationException(errorMessage, e);
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
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) {
        return registerFlow(AuthType.OTT, customizer, OttDslConfigurerImpl::new);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) {
        return registerFlow(AuthType.PASSKEY, customizer, PasskeyDslConfigurerImpl::new);
    }

    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        return registerMultiStepFlow(customizer, MfaDslConfigurerImpl::new);
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
