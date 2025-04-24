package io.springsecurity.springsecurity6x.security.configurer.state;

import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import io.springsecurity.springsecurity6x.security.utils.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;

public class JwtStateStrategy implements AuthenticationStateStrategy {

    private TokenService tokenService;
    private String tokenPrefix = "Bearer ";
    public static long accessTokenValidity = 3600000;     // default: 1 hour
    public static long refreshTokenValidity = 604800000;  // default: 7 days
    private boolean enableRefreshToken = true;

    public JwtStateStrategy tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
        return this;
    }

    public JwtStateStrategy tokenPrefix(String prefix) {
        this.tokenPrefix = prefix;
        return this;
    }

    public JwtStateStrategy accessTokenValidity(long millis) {
        accessTokenValidity = millis;
        return this;
    }

    public JwtStateStrategy refreshTokenValidity(long millis) {
        refreshTokenValidity = millis;
        return this;
    }

    public JwtStateStrategy enableRefreshToken(boolean enable) {
        this.enableRefreshToken = enable;
        return this;
    }

    public TokenService tokenService() {
        return tokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        String accessToken = tokenService.createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .validity(accessTokenValidity));

        String refreshToken = enableRefreshToken ?
                    tokenService.createRefreshToken(builder -> builder
                            .username(username)
                            .roles(roles)
                            .validity(refreshTokenValidity)) : null;

        CookieUtil.addTokenCookie(request, response, "accessToken", accessToken);
        if (refreshToken != null) {
            CookieUtil.addTokenCookie(request, response, "refreshToken", refreshToken);
        }

        response.setStatus(HttpServletResponse.SC_OK);
    }
}

