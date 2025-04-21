package io.springsecurity.springsecurity6x.jwt.properties;

import lombok.Data;

import java.time.Duration;

@Data
public class InternalTokenSettings {

    private Duration accessTokenTtl = Duration.ofMinutes(30);
    private Duration refreshTokenTtl = Duration.ofDays(7);

    private String clientId = "internal-client";
    private String clientSecret = "{noop}secret";

}

