package io.springsecurity.springsecurity6x.security.init.option;

import lombok.Data;

import java.util.List;

@Data
public class RestOptions {
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
}
