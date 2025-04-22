package io.springsecurity.springsecurity6x.security.properties;

import lombok.Data;

@Data
public class InternalTokenSettings {

    private String clientId = "internal-client";
    private String clientSecret = "{noop}secret";

    private long accessTokenTtl = 3600000;     // 1시간
    private long refreshTokenTtl = 604800000;  // 7일
}

