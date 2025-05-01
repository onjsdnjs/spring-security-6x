package io.springsecurity.springsecurity6x.security.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

public class IdentityConfig {

    public List<AuthenticationConfig<?>> authentications = new ArrayList<>();
    private Customizer<HttpSecurity> httpCustomizer;

    public <T>  void addConfig(String type, T options, String stateType) {
        AuthenticationConfig<T> config = new AuthenticationConfig<>();
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
