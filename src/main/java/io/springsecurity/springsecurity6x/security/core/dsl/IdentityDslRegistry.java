package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttStepDslConfigurer; // 추가
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyStepDslConfigurer; // 추가
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.OttDslConfigurerImpl; // Step-Aware 버전
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.PasskeyDslConfigurerImpl; // Step-Aware 버전
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Slf4j
@Component
public class IdentityDslRegistry extends AbstractFlowRegistrar {

    public IdentityDslRegistry(ApplicationContext applicationContext) {
        super(PlatformConfig.builder(), applicationContext);
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");
    }

    @Override
    public SecurityPlatformDsl global(SafeHttpCustomizer customizer) {
        platformBuilder.global(wrapSafeGlobalCustomizer(customizer));
        return this;
    }

    private Customizer<HttpSecurity> wrapSafeGlobalCustomizer(SafeHttpCustomizer safeCustomizer) {
        return http -> {
            try {
                if (safeCustomizer != null) {
                    safeCustomizer.customize(http);
                }
            } catch (Exception e) {
                String errorMessage = String.format("Error during global HttpSecurity customization: %s", e.getMessage());
                log.error(errorMessage, e);
                throw new DslConfigurationException(errorMessage, e);
            }
        };
    }

    @Override
    public IdentityStateDsl form(Customizer<FormStepDslConfigurer> customizer) {
        return registerFlow(AuthType.FORM, customizer,
                FormDslConfigurerImpl::new
        );
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestStepDslConfigurer> customizer) {
        return registerFlow(AuthType.REST, customizer,
                RestDslConfigurerImpl::new
        );
    }

    // 단일 인증 흐름으로 OTT 지원
    @Override
    public IdentityStateDsl ott(Customizer<OttStepDslConfigurer> customizer) {
        return registerFlow(AuthType.OTT, customizer,
                (stepConfig) -> new OttDslConfigurerImpl(stepConfig, this.applicationContext)
        );
    }

    // 단일 인증 흐름으로 Passkey 지원
    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyStepDslConfigurer> customizer) {
        return registerFlow(AuthType.PASSKEY, customizer,
                PasskeyDslConfigurerImpl::new
        );
    }

    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        return registerMultiStepFlow(customizer,
                MfaDslConfigurerImpl::new);
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
