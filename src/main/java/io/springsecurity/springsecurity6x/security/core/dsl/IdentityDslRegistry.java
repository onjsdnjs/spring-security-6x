package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslConfigurerImpl;
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

    // --- 단일 인증 흐름으로 OTT 및 Passkey를 지원하지 않음 ---
    // 이들은 현재 MFA의 Factor로만 사용됩니다.
    // 만약 단일 인증 흐름으로 사용하려면, 각 Configurer 구현 (OttDslConfigurerImpl, PasskeyDslConfigurerImpl)이
    // AbstractStepAwareDslConfigurer를 상속하고 AuthenticationStepConfig를 생성자의 첫 번째 인자로 받도록 수정해야 하며,
    // ApplicationContext가 필요한 경우 registerFlow의 factory 람다식에서 this.applicationContext를 사용하여 전달해야 합니다.
    // 현재 OttDslConfigurerImpl, PasskeyDslConfigurerImpl은 MFA Factor 용으로 설계되어
    // AbstractOptionsBuilderConfigurer를 상속하고 ApplicationContext를 생성자에서 받거나 받지 않습니다.
    // 따라서 아래 메소드들은 현재 설계와 맞지 않아 제거하거나 주석 처리합니다.

    /*
    @Override
    public IdentityStateDsl ott(Customizer<OttStepDslConfigurer> customizer) {
        // OttDslConfigurerImpl은 ApplicationContext를 필요로 함.
        // 또한, 단일 스텝으로 사용되려면 OttStepDslConfigurer 인터페이스가 StepDslConfigurer를 확장해야 하고,
        // OttDslConfigurerImpl이 AbstractStepAwareDslConfigurer를 상속해야 함.
        // 현재는 MFA Factor 용도로만 사용되므로, 이 메소드는 주석 처리.
        // return registerFlow(AuthType.OTT, customizer,
        //        (stepConfig) -> new OttDslConfigurerImpl(stepConfig, this.applicationContext) // 생성자 시그니처 불일치
        // );
        throw new UnsupportedOperationException("Single-step OTT flow is not supported via this method. Use within MFA flow.");
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyStepDslConfigurer> customizer) {
        // PasskeyDslConfigurerImpl은 ApplicationContext를 필요로 하지 않음.
        // 단일 스텝으로 사용되려면 PasskeyStepDslConfigurer 인터페이스가 StepDslConfigurer를 확장해야 하고,
        // PasskeyDslConfigurerImpl이 AbstractStepAwareDslConfigurer를 상속해야 함.
        // 현재는 MFA Factor 용도로만 사용되므로, 이 메소드는 주석 처리.
        // return registerFlow(AuthType.PASSKEY, customizer,
        //        (stepConfig) -> new PasskeyDslConfigurerImpl(stepConfig) // 생성자 시그니처 불일치
        // );
        throw new UnsupportedOperationException("Single-step Passkey flow is not supported via this method. Use within MFA flow.");
    }
    */

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
