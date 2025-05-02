package io.springsecurity.springsecurity6x.security.init.option;

import lombok.Data;

import java.util.List;

@Data
public class PasskeyOptions {
    private String rpName;
    private String rpId;
    private String[] allowedOrigins;
    private List<String> matchers;

    public List<String> matchers() {
        return matchers;
    }

    public void matchers(List<String> matchers) {
        this.matchers = matchers;
    }
}
