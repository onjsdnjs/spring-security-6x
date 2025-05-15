package io.springsecurity.springsecurity6x.security.core.dsl.factory;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.FormDslOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery.RecoveryCodeFactorDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;

public class FactorDslConfigurerFactory {

    private final ApplicationContext applicationContext;

    public FactorDslConfigurerFactory(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    // 반환 타입을 더 구체적인 인터페이스로 변경
    public <D extends OptionsBuilderDsl<O, D>, O extends FactorAuthenticationOptions> D createConfigurer(AuthType factorType) {
        return switch (factorType) {
            case FORM -> (D) new FormDslOptionsBuilderConfigurer();
            case REST -> (D) new RestDslOptionsBuilderConfigurer();
            case OTT -> (D) new OttFactorDslConfigurerImpl(this.applicationContext);
            case PASSKEY -> (D) new PasskeyFactorDslConfigurerImpl();
            case RECOVERY_CODE -> (D) new RecoveryCodeFactorDslConfigurerImpl(); // 정의 필요
            default -> throw new IllegalArgumentException("Unsupported factorType: " + factorType);
        };
    }
}
