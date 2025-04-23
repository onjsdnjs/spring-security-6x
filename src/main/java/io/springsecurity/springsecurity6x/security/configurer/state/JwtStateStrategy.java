package io.springsecurity.springsecurity6x.security.configurer.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtStateStrategy implements AuthenticationStateStrategy {

    private TokenService tokenService;
    private String tokenPrefix = "Bearer ";
    private long accessTokenValidity = 3600000;     // default: 1 hour
    private long refreshTokenValidity = 604800000;  // default: 7 days
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
        this.accessTokenValidity = millis;
        return this;
    }

    public JwtStateStrategy refreshTokenValidity(long millis) {
        this.refreshTokenValidity = millis;
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

        // 1) 토큰 생성
        String accessToken = tokenService.createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .validity(accessTokenValidity));

        String refreshToken = enableRefreshToken
                ? tokenService.createRefreshToken(builder -> builder
                .username(username)
                .validity(refreshTokenValidity))
                : null;

        // 2) HTTP-only, Secure 쿠키에 담아서 응답
        Cookie accessCookie = new Cookie("accessToken", tokenPrefix + accessToken);
        accessCookie.setHttpOnly(true);
//        accessCookie.setSecure(true);         // HTTPS 환경이면 true
        accessCookie.setPath("/");
        accessCookie.setMaxAge((int)(accessTokenValidity / 1000));
        response.addCookie(accessCookie);

        if (refreshToken != null) {
            Cookie refreshCookie = new Cookie("refreshToken", tokenPrefix + refreshToken);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true);
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge((int)(refreshTokenValidity / 1000));
            response.addCookie(refreshCookie);
        }

        // 3) (선택) JSON 응답 바디 대신 상태 코드만 내려도 되고,
        //    필요하면 쿠키만 보내고 바로 리다이렉트할 수도 있습니다.
        //    여기서는 예시로 간단히 200 OK만 반환합니다.
        response.setStatus(HttpServletResponse.SC_OK);
    }
}

