package io.springsecurity.springsecurity6x.security.token.service;

import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;


public interface TokenService {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";

    String createAccessToken(Authentication authentication);

    String createRefreshToken(Authentication authentication);


}

