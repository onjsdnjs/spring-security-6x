package io.springsecurity.springsecurity6x.security.core.dsl.factory;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery.RecoveryCodeFactorDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

public class FactorDslConfigurerFactory {

    private final ApplicationContext applicationContext;

    public FactorDslConfigurerFactory(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    // 반환 타입을 더 구체적인 인터페이스로 변경
    public <T extends OptionsBuilderDsl<? extends FactorAuthenticationOptions, T>> T createConfigurer(AuthType factorType) {
        Assert.notNull(factorType, "factorType cannot be null");
        switch (factorType) {
            case PASSKEY:
                return (T) new PasskeyFactorDslConfigurerImpl();
            case OTT:
                return (T) new OttFactorDslConfigurerImpl(this.applicationContext);
            case RECOVERY_CODE:
                return (T) new RecoveryCodeFactorDslConfigurerImpl();
            default:
                throw new IllegalArgumentException("No FactorDslConfigurer implementation registered for AuthType: " + factorType);
        }
    }
}
