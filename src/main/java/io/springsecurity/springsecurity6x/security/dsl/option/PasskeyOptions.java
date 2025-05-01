package io.springsecurity.springsecurity6x.security.dsl.option;

import lombok.Data;

import java.util.List;

@Data
public class PasskeyOptions {
    private String rpName;
    private String rpId;
    private String[] allowedOrigins;
    private List<String> matchers;
}
