package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.*;
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

    // PlatformConfig.Builder를 명시적으로 받도록 수정 (기존 코드와 동일하게 유지)
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
                if (safeCustomizer != null) { // customizer가 null일 수 있으므로 체크
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
        // FormDslConfigurerImpl은 ApplicationContext를 필요로 하지 않음.
        return registerFlow(AuthType.FORM, customizer,
                (stepConfig) -> new FormDslConfigurerImpl(stepConfig)
        );
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestStepDslConfigurer> customizer) {
        // RestDslConfigurerImpl은 ApplicationContext를 필요로 하지 않음.
        return registerFlow(AuthType.REST, customizer,
                (stepConfig) -> new RestDslConfigurerImpl(stepConfig)
        );
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttStepDslConfigurer> customizer) {
        return registerFlow(AuthType.OTT, customizer,
                // OttDslConfigurerImpl (Step-Aware 버전)은 AuthenticationStepConfig와 ApplicationContext를 받음
                (stepConfig) -> new OttDslConfigurerImpl(stepConfig, this.applicationContext)
        );
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyStepDslConfigurer> customizer) {
        // PasskeyDslConfigurerImpl (Step-Aware 버전)은 AuthenticationStepConfig를 받음
        return registerFlow(AuthType.PASSKEY, customizer,
                (stepConfig) -> new PasskeyDslConfigurerImpl(stepConfig)
        );
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        // MfaDslConfigurerImpl은 AuthenticationFlowConfig.Builder와 ApplicationContext를 필요로 함.
        return registerMultiStepFlow(customizer,
                (flowBuilder) -> new MfaDslConfigurerImpl(flowBuilder, this.applicationContext));
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
