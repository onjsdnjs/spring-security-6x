package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.dsl.option.DslOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

public class IdentityConfig {

    public List<AuthenticationConfig> authentications = new ArrayList<>();
    private Customizer<HttpSecurity> httpCustomizer;

    public void addConfig(String type, DslOptions options, String stateType) {
        AuthenticationConfig config = new AuthenticationConfig();
        config.type = type;
        config.options = options;
        config.stateType = stateType;
        this.authentications.add(config);
    }

    public void httpCustomizer(Customizer<HttpSecurity> customizer) {
        this.httpCustomizer = customizer;
    }

    public Customizer<HttpSecurity> httpCustomizer() {
        return httpCustomizer;
    }
}
