package io.springsecurity.springsecurity6x.security.init.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import lombok.Data;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

@Data
public class OttOptions implements AuthConfigurer {
    private String loginProcessingUrl;
    private List<String> matchers;

    public String loginProcessingUrl() {
        return loginProcessingUrl;
    }

    public void loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
    }

    public List<String> matchers() {
        return matchers;
    }

    public void matchers(List<String> matchers) {
        this.matchers = matchers;
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