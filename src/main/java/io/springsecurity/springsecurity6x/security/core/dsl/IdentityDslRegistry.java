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
import org.springframework.util.Assert;

@Slf4j
public class IdentityDslRegistry extends AbstractFlowRegistrar {

    private final ApplicationContext applicationContext;

    public IdentityDslRegistry(PlatformConfig.Builder platformBuilder, ApplicationContext applicationContext) {
        super(platformBuilder);
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");
        this.applicationContext = applicationContext;
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
                (stepConfig) -> new FormDslConfigurerImpl(stepConfig)
        );
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestStepDslConfigurer> customizer) {
        return registerFlow(AuthType.REST, customizer,
                (stepConfig) -> new RestDslConfigurerImpl(stepConfig)
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
                (stepConfig) -> new PasskeyDslConfigurerImpl(stepConfig)
        );
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        return registerMultiStepFlow(customizer,
                (flowBuilder) -> new MfaDslConfigurerImpl(flowBuilder, this.applicationContext));
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
