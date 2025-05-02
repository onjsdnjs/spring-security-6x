package io.springsecurity.springsecurity6x.security.init.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import lombok.Data;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Arrays;
import java.util.List;

@Data
public class PasskeyOptions implements AuthConfigurer {
    private String rpName;
    private String rpId;
    private List<String> allowedOrigins;
    private List<String> matchers;

    public List<String> matchers() {
        return matchers;
    }

    public void matchers(List<String> matchers) {
        this.matchers = matchers;
    }

    public PasskeyOptions rpId(String rpId) {
        this.rpId = rpId;
        return this;
    }

    public PasskeyOptions rpName(String rpName) {
        this.rpName = rpName;
        return this;
    }

    public PasskeyOptions allowedOrigins(String... origins) {
        this.allowedOrigins = Arrays.asList(origins);
        return this;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        if (matchers != null && !matchers.isEmpty()) {
            http.securityMatcher(matchers.toArray(new String[0]));
        } else {
            http.securityMatcher("/**");
        }
    }
}
