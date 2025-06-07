package io.springsecurity.springsecurity6x.security.authz.context;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

/**
 * 웹 계층의 요청을 인가 엔진이 사용할 표준 컨텍스트로 변환하는 책임.
 */
public interface ContextHandler {
    AuthorizationContext create(Authentication authentication, HttpServletRequest request);
}
