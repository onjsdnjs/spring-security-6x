package io.springsecurity.springsecurity6x.security.init.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

public class FormOptions implements AuthConfigurer {

    private String loginPage;
    private List<String> matchers;

    public String loginPage() {
        return loginPage;
    }

    public void loginPage(String loginPage) {
        this.loginPage = loginPage;
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