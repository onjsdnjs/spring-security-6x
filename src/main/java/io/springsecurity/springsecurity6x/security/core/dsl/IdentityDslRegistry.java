package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

@Component // Spring Component로 등록
public class IdentityDslRegistry extends AbstractFlowRegistrar {

    public IdentityDslRegistry(ApplicationContext applicationContext) {
        super(PlatformConfig.builder(), applicationContext);
    }

    @Override
    public SecurityPlatformDsl global(SafeHttpCustomizer<HttpSecurity> customizer) {
        platformBuilder.global(customizer);
        return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) {
        return registerAuthenticationMethod(AuthType.FORM, customizer, 100); // 기본 order 값 예시
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) {
        return registerAuthenticationMethod(AuthType.REST, customizer, 200);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) {
        return registerAuthenticationMethod(AuthType.OTT, customizer, 300);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) {
        return registerAuthenticationMethod(AuthType.PASSKEY, customizer, 400);
    }

    // RECOVERY_CODE를 단일 인증 흐름으로 사용하기 위한 DSL 메소드 (선택적 추가)
    // public IdentityStateDsl recoveryCode(Customizer<RecoveryCodeConfigurer> customizer) {
    //     return registerAuthenticationMethod(AuthType.RECOVERY_CODE, customizer, 450);
    // }


    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        return registerMultiStepFlow(customizer, MfaDslConfigurerImpl::new);
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
