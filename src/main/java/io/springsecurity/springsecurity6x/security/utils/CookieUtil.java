package io.springsecurity.springsecurity6x.security.utils;

import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * ResponseCookie 기반으로 HTTP 응답에 Set-Cookie 헤더를 추가해 주는 유틸리티 클래스
 */
public final class CookieUtil {

    private CookieUtil() {
        // 인스턴스 생성 방지
    }

    /**
     * accessToken 쿠키를 생성하여 응답 헤더에 추가한다.
     *
     * @param request     현재 HTTP 요청 (secure 여부 확인용)
     * @param response    HTTP 응답 객체
     * @param accessToken 발급된 액세스 토큰
     * @param cookieName 쿠키명
     */
    public static void addTokenCookie(HttpServletRequest request, HttpServletResponse response, String cookieName, String accessToken) {

        ResponseCookie cookie = ResponseCookie.from(cookieName, accessToken)
                .httpOnly(true)                               // js 에서 접근 불가
                .secure(request.isSecure())                   // HTTPS 요청일 때만 전송
                .path("/")                                     // 전체 경로에서 유효
                .maxAge(JwtStateStrategy.ACCESS_TOKEN_VALIDITY / 1000)  // 유효기간(초)
                .sameSite("Strict")                            // CSRF 방어용 SameSite
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
