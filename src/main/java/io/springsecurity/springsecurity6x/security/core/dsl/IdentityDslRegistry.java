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

@Slf4j
public class IdentityDslRegistry extends AbstractFlowRegistrar {

    private final ApplicationContext applicationContext; // 추가

    public IdentityDslRegistry(PlatformConfig.Builder platformBuilder, ApplicationContext applicationContext) { // 생성자 수정
        super(platformBuilder);
        this.applicationContext = applicationContext; // 주입
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

    // registerFlow의 Customizer 타입을 Step Aware 버전으로 변경하고, factory도 ApplicationContext를 받도록 수정
    @Override
    public IdentityStateDsl form(Customizer<FormStepDslConfigurer> customizer) {
        return registerFlow(AuthType.FORM, customizer,
                (stepConfig) -> new FormDslConfigurerImpl(stepConfig) // ApplicationContext 불필요
        );
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestStepDslConfigurer> customizer) {
        return registerFlow(AuthType.REST, customizer,
                (stepConfig) -> new RestDslConfigurerImpl(stepConfig) // ApplicationContext 불필요
        );
    }

    // 만약 OTT, Passkey를 단일 인증 스텝으로 사용하고 싶다면, 이들도 StepAware 버전의 Configurer와 인터페이스가 필요합니다.
    // 현재는 Factor 로만 사용되므로, registerFactor 내에서 OptionsBuilder 버전이 사용됩니다.
    // 여기서는 일단 주석 처리하거나, 해당 StepAware Configurer를 정의해야 합니다.
    /*
    @Override
    public IdentityStateDsl ott(Customizer<OttStepDslConfigurer> customizer) { // OttStepDslConfigurer 인터페이스 필요
        return registerFlow(AuthType.OTT, customizer,
                (stepConfig) -> new OttDslConfigurerImpl(stepConfig, this.applicationContext) // OttDslConfigurerImpl이 StepAware 버전이라고 가정
        );
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyStepDslConfigurer> customizer) { // PasskeyStepDslConfigurer 인터페이스 필요
        return registerFlow(AuthType.PASSKEY, customizer,
                (stepConfig) -> new PasskeyDslConfigurerImpl(stepConfig) // PasskeyDslConfigurerImpl이 StepAware 버전이라고 가정
        );
    }
    */

    // AbstractFlowRegistrar의 registerFlow 메소드 시그니처도 변경되어야 함.
    // Function<AuthenticationStepConfig, I>  ->  BiFunction<AuthenticationStepConfig, ApplicationContext, I>
    // 또는 Function<AuthenticationStepConfig, I> 를 유지하고, 람다에서 this.applicationContext를 클로저로 사용.
    // 여기서는 후자를 선택한 것으로 간주하고, AbstractFlowRegistrar의 registerFlow는 그대로 둔다고 가정.
    // 단, OttDslConfigurerImpl 등이 AuthenticationStepConfig를 받는 생성자가 있어야 함.
    // 이는 현재 설계(Factor는 OptionsBuilder만 사용)와 충돌하므로, 단일 스텝 OTT/Passkey는 다른 방식으로 처리해야 함.
    // 가장 간단하게는 해당 registerFlow 메소드를 삭제하거나, 해당 ConfigurerImpl이 StepAware와 OptionsBuilder 모두를 지원하도록 매우 복잡하게 만들어야함.
    // 현재는 MFA의 Factor 로만 사용되므로, 위의 ott(), passkey()는 삭제하거나 주석처리하는 것이 맞습니다.

    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        return registerMultiStepFlow(customizer,
                builder -> new MfaDslConfigurerImpl(builder, this.applicationContext)); // ApplicationContext 전달
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
