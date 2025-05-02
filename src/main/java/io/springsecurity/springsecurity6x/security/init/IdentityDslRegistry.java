package io.springsecurity.springsecurity6x.security.init;

import io.springsecurity.springsecurity6x.security.init.option.FormOptions;
import io.springsecurity.springsecurity6x.security.init.option.OttOptions;
import io.springsecurity.springsecurity6x.security.init.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.init.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


/**
 * DSL 선언을 수집하고 IdentityConfig에 위임하는 조립기 클래스.
 */
public class IdentityDslRegistry {

    private final IdentityConfig config;
    private Customizer<HttpSecurity> customizer;

    public IdentityDslRegistry() {
        this.config = new IdentityConfig();
    }

    public IdentityStateDsl form(Customizer<FormOptions> customizer) {
        return apply(AuthType.FORM, new FormOptions(), customizer);
    }

    public IdentityStateDsl ott(Customizer<OttOptions> customizer) {
        return apply(AuthType.OTT, new OttOptions(), customizer);
    }

    public IdentityStateDsl passkey(Customizer<PasskeyOptions> customizer) {
        return apply(AuthType.PASSKEY, new PasskeyOptions(), customizer);
    }

    public IdentityStateDsl rest(Customizer<RestOptions> customizer) {
        return apply(AuthType.REST, new RestOptions(), customizer);
    }

    private <T> IdentityStateDsl apply(AuthType type, T options, Customizer<T> customizer) {

        customizer.customize(options);

        return new IdentityStateDsl() {
            @Override
            public IdentityDslRegistry useJwt() {
                config.add(AuthenticationConfigFactory.create(type, options, StateType.JWT, customizer));
                return IdentityDslRegistry.this;
            }

            @Override
            public IdentityDslRegistry useSession() {
                config.add(AuthenticationConfigFactory.create(type, options, StateType.SESSION, customizer));
                return IdentityDslRegistry.this;
            }
        };
    }

    public IdentityConfig config() {
        return config;
    }

    public IdentityDslRegistry customize(Customizer<HttpSecurity> customizer) {
        this.customizer = customizer;
        return this;
    }

    public Customizer<HttpSecurity> customizer() {
        return customizer;
    }
}