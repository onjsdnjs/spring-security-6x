package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.*;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

public class IdentityDslRegistry implements SecurityPlatformDsl {
    private final PlatformConfig config = new PlatformConfig();

    @Override
    public SecurityPlatformDsl global(Customizer<HttpSecurity> customizer) {
        config.setGlobal(customizer);
        return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormDslConfigurer> customizer) {
        FormDslConfigurerImpl impl = new FormDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.FORM.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                impl.toFlowCustomizer()
        ));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer) {
        RestDslConfigurerImpl impl = new RestDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.REST.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                impl.toFlowCustomizer()
        ));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer) {
        OttDslConfigurerImpl impl = new OttDslConfigurerImpl();
        customizer.customize(impl);
        config.addFlow(new AuthenticationFlowConfig(
                AuthType.OTT.name().toLowerCase(),
                List.of(impl.toConfig()),
                null,
                impl.toFlowCustomizer()
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
                impl.toFlowCustomizer()
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
                null
        ));
        return new StateSetter(this);
    }

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
        public SecurityPlatformDsl session() {
            registry.setLastState(StateType.SESSION.name().toLowerCase());
            return registry;
        }

        @Override
        public SecurityPlatformDsl jwt() {
            registry.setLastState(StateType.JWT.name().toLowerCase());
            return registry;
        }

        @Override
        public SecurityPlatformDsl oauth2() {
            registry.setLastState(StateType.OAUTH2.name().toLowerCase());
            return registry;
        }
    }

    private void setLastState(String stateId) {
        var flow = config.getFlows().get(config.getFlows().size() - 1);
        flow.setState(new StateConfig(stateId));
    }
}
