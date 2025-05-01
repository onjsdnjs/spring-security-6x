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
    private Customizer<HttpSecurity> httpCustomizer;

    @Override
    public FormDsl form(Customizer<FormDsl> customizer) {
        FormOptions options = new FormOptions();
        FormDsl dsl = new FormDsl() {
            public FormDsl loginPage(String url) {
                options.set("loginPage", url);
                return this;
            }
            public FormDsl matchers(String... patterns) {
                options.set("matchers", Arrays.asList(patterns));
                return this;
            }
            public IdentityStateDsl useSession() {
                config.addConfig("form", options, "session");
                return IdentityDslImpl.this;
            }
            public IdentityStateDsl useJwt() {
                config.addConfig("form", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return null;
    }

    @Override
    public RestDsl rest(Customizer<RestDsl> customizer) {
        RestOptions options = new RestOptions();
        RestDsl dsl = new RestDsl() {
            public RestDsl loginProcessingUrl(String url) {
                options.set("loginProcessingUrl", url);
                return this;
            }
            public IdentityStateDsl useSession() {
                config.addConfig("rest", options, "session");
                return IdentityDslImpl.this;
            }
            public IdentityStateDsl useJwt() {
                config.addConfig("rest", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return null;
    }

    @Override
    public PasskeyDsl passkey(Customizer<PasskeyDsl> customizer) {
        PasskeyOptions options = new PasskeyOptions();
        PasskeyDsl dsl = new PasskeyDsl() {
            public PasskeyDsl rpName(String name) {
                options.set("rpName", name);
                return this;
            }
            public PasskeyDsl rpId(String id) {
                options.set("rpId", id);
                return this;
            }
            public PasskeyDsl allowedOrigins(String... origins) {
                options.set("allowedOrigins", origins);
                return this;
            }
            public IdentityStateDsl useSession() {
                config.addConfig("passkey", options, "session");
                return IdentityDslImpl.this;
            }
            public IdentityStateDsl useJwt() {
                config.addConfig("passkey", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return null;
    }

    @Override
    public OttDsl ott(Customizer<OttDsl> customizer) {
        OttOptions options = new OttOptions();
        OttDsl dsl = new OttDsl() {
            public OttDsl loginProcessingUrl(String url) {
                options.set("loginProcessingUrl", url);
                return this;
            }
            public OttDsl matchers(String... patterns) {
                options.set("matchers", Arrays.asList(patterns));
                return this;
            }
            public IdentityStateDsl useSession() {
                config.addConfig("ott", options, "session");
                return IdentityDslImpl.this;
            }
            public IdentityStateDsl useJwt() {
                config.addConfig("ott", options, "jwt");
                return IdentityDslImpl.this;
            }
        };
        customizer.customize(dsl);
        return null;
    }

    @Override
    public IdentityStateDsl customize(Customizer<HttpSecurity> customizer) {
        this.httpCustomizer = customizer;
        return this;
    }

    public IdentityConfig getConfig() {
        config.httpCustomizer(httpCustomizer);
        return config;
    }
}