package io.springsecurity.springsecurity6x.security.init.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import lombok.Data;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

public class RestOptions implements AuthConfigurer {

    private List<String> matchers;
    private String loginProcessingUrl;

    public RestOptions matchers(List<String> matchers) {
        this.matchers = matchers;
        return this;
    }

    public RestOptions loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
        return this;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        if (matchers != null && !matchers.isEmpty()) {
            http.securityMatcher(matchers.toArray(new String[0]));
        } else {
            http.securityMatcher("/api/**");
        }
    }
}
