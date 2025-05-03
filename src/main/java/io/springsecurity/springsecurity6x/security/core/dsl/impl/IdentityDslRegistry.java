package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.function.Consumer;

public class IdentityDslRegistry implements SecurityPlatformDsl {

    private final PlatformConfig config = new PlatformConfig();

    @Override
    public SecurityPlatformDsl global(Customizer<HttpSecurity> customizer) {
        config.setGlobal(customizer);
        return this;
    }

    @Override
    public IdentityStateDsl form(Consumer<FormDslConfigurer> consumer) {
        FormDslConfigurer impl = new FormDslConfigurerImpl();
        consumer.accept(impl);
        config.addFlow(new AuthenticationFlowConfig("form", List.of(impl.toConfig()), null));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl rest(Consumer<RestDslConfigurer> consumer) {
        RestDslConfigurerImpl impl = new RestDslConfigurerImpl();
        consumer.accept(impl);
        config.addFlow(new AuthenticationFlowConfig("rest", List.of(impl.toConfig()), null));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl ott(Consumer<OttDslConfigurer> consumer) {
        OttDslConfigurerImpl impl = new OttDslConfigurerImpl();
        consumer.accept(impl);
        config.addFlow(new AuthenticationFlowConfig("ott", List.of(impl.toConfig()), null));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl passkey(Consumer<PasskeyDslConfigurer> consumer) {
        PasskeyDslConfigurerImpl impl = new PasskeyDslConfigurerImpl();
        consumer.accept(impl);
        config.addFlow(new AuthenticationFlowConfig("passkey", List.of(impl.toConfig()), null));
        return new StateSetter(this);
    }

    @Override
    public IdentityStateDsl mfa(Consumer<MfaDslConfigurer> consumer) {
        MfaDslConfigurerImpl impl = new MfaDslConfigurerImpl();
        consumer.accept(impl);
        config.addFlow(new AuthenticationFlowConfig("mfa", impl.getAuthConfigs(), null));
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
            registry.setLastState("session");
            return registry;
        }

        @Override
        public SecurityPlatformDsl jwt() {
            registry.setLastState("jwt");
            return registry;
        }

        @Override
        public SecurityPlatformDsl oauth2() {
            registry.setLastState("oauth2");
            return registry;
        }
    }

    private void setLastState(String stateId) {
        var flow = config.getFlows().get(config.getFlows().size() - 1);
        flow.setState(new StateConfig(stateId));
    }
}
