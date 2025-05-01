package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.config.IdentityConfig;
import io.springsecurity.springsecurity6x.security.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.dsl.option.RestOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Arrays;

public class IdentityDslImpl implements IdentityDsl, IdentityStateDsl {

    private final IdentityConfig config = new IdentityConfig();

    @Override
    public FormDsl form(Customizer<FormDsl> customizer) {
        FormOptions options = new FormOptions();
        FormDsl dsl = new FormDsl() {
            public FormDsl matchers(String... patterns) {
                options.setMatchers(Arrays.asList(patterns));
                return this;
            }

            @Override
            public FormDsl loginPage(String url) {
                options.setLoginPage(url);
                return this;
            }

            @Override
            public IdentityStateDsl useSession() {
                config.addConfig("form", options, "session");
                return IdentityDslImpl.this;
            }

            @Override
            public IdentityStateDsl useJwt() {
                config.addConfig("form", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return dsl;
    }

    @Override
    public RestDsl rest(Customizer<RestDsl> customizer) {
        RestOptions options = new RestOptions();
        RestDsl dsl = new RestDsl() {
            @Override
            public RestDsl matchers(String... patterns) {
                return null;
            }

            @Override
            public RestDsl loginProcessingUrl(String url) {
                options.setLoginProcessingUrl(url);
                return this;
            }

            @Override
            public IdentityStateDsl useSession() {
                config.addConfig("rest", options, "session");
                return IdentityDslImpl.this;
            }

            @Override
            public IdentityStateDsl useJwt() {
                config.addConfig("rest", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return dsl;
    }

    @Override
    public PasskeyDsl passkey(Customizer<PasskeyDsl> customizer) {
        PasskeyOptions options = new PasskeyOptions();
        PasskeyDsl dsl = new PasskeyDsl() {
            @Override
            public PasskeyDsl matchers(String... patterns) {
                return null;
            }

            @Override
            public PasskeyDsl rpName(String name) {
                options.setRpName(name);
                return this;
            }

            @Override
            public PasskeyDsl rpId(String id) {
                options.setRpId(id);
                return this;
            }

            @Override
            public PasskeyDsl allowedOrigins(String... origins) {
                options.setAllowedOrigins(origins);
                return this;
            }

            @Override
            public IdentityStateDsl useSession() {
                config.addConfig("passkey", options, "session");
                return IdentityDslImpl.this;
            }

            @Override
            public IdentityStateDsl useJwt() {
                config.addConfig("passkey", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return dsl;
    }

    @Override
    public OttDsl ott(Customizer<OttDsl> customizer) {
        OttOptions options = new OttOptions();
        OttDsl dsl = new OttDsl() {
            @Override
            public OttDsl matchers(String... patterns) {
                return null;
            }

            @Override
            public OttDsl loginProcessingUrl(String url) {
                options.setLoginProcessingUrl(url);
                return this;
            }

            @Override
            public IdentityStateDsl useSession() {
                config.addConfig("ott", options, "session");
                return IdentityDslImpl.this;
            }

            @Override
            public IdentityStateDsl useJwt() {
                config.addConfig("ott", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return dsl;
    }

    @Override
    public IdentityStateDsl customize(Customizer<HttpSecurity> httpCustomizer) throws Exception {
        return null;
    }

    public IdentityConfig getConfig() {
        return config;
    }
}