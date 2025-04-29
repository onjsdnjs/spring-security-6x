package io.springsecurity.springsecurity6x.security.properties;

import lombok.Data;

@Data
public class JwtsTokenSettings {

    private String loginUri = "/api/auth/login";
    private String logoutUri = "/api/auth/logout";
    private String refreshUri = "/api/auth/refresh";
}

