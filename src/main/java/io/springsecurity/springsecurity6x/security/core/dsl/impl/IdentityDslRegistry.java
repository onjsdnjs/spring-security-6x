package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityStateDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.SecurityPlatformDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

public class IdentityDslRegistry implements SecurityPlatformDsl {

    private final PlatformConfig config = new PlatformConfig();

    @Override
    public SecurityPlatformDsl originGlobal(Customizer<HttpSecurity> customizer){
        config.global(customizer);
        return this;
    }

    public SecurityPlatformDsl global(SafeHttpCustomizer customizer) {
        return originGlobal(wrapSafe(customizer));
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                System.err.println("Global customizer exception: " + e.getMessage());
            }
        };
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) {

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        FormDslConfigurerImpl impl = new FormDslConfigurerImpl(stepConfig);
        customizer.customize(impl);
        AuthenticationStepConfig step = impl.toConfig();

        config.addFlow(new AuthenticationFlowConfig(
                AuthType.FORM.name().toLowerCase(),  // flow type
                List.of(step),                       // step configs
                null,                                // state (session/jwt 등은 StateSetter로)
                http -> {}                           // flow-level customizer는 사용하지 않음
        ));

        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) {
        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        RestDslConfigurerImpl impl = new RestDslConfigurerImpl(stepConfig);
        customizer.customize(impl);
        AuthenticationStepConfig step = impl.toConfig();
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.REST.name().toLowerCase(),
                List.of(step),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }
    /*
    @Override
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) {
        OttDslConfigurerImpl impl = new OttDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.OTT.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer) {
        PasskeyDslConfigurerImpl impl = new PasskeyDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.PASSKEY.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) {
        MfaDslConfigurerImpl impl = new MfaDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.MFA.name().toLowerCase(),
                impl.getAuthConfigs(),
                null,
                http -> {}
        ));
        return new StateSetter(this);
    }*/

    @Override
    public PlatformConfig build() {
        return config;
    }

    private static class StateSetter implements IdentityStateDsl {
        private final IdentityDslRegistry registry;

        StateSetter(IdentityDslRegistry registry) {
            this.registry = registry;
        }

        @Override
        public SecurityPlatformDsl session(Customizer<FormDslConfigurer> customizer) {
            registry.setLastState(StateType.SESSION.name().toLowerCase());
            return registry;
        }

        @Override
        public SecurityPlatformDsl jwt(Customizer<FormDslConfigurer> customizer) {
            registry.setLastState(StateType.JWT.name().toLowerCase());
            return registry;
        }

        @Override
        public SecurityPlatformDsl oauth2(Customizer<FormDslConfigurer> customizer) {
            registry.setLastState(StateType.OAUTH2.name().toLowerCase());
            return registry;
        }
    }

    private void setLastState(String stateId) {
        var flow = config.flows().get(config.flows().size() - 1);
        flow.stateConfig(new StateConfig(stateId));
    }
}
