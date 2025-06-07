package io.springsecurity.springsecurity6x.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface PolicyEngine {
    /**
     * 주어진 컨텍스트에 대해 인가를 평가합니다.
     * @param authentication 현재 인증된 사용자 정보
     * @param request 현재 HTTP 요청
     * @param targetObject 보호 대상 객체 (메서드 인가 시 사용될 수 있음)
     * @return 인가 여부 (true: 허용, false: 거부)
     */
    boolean evaluate(Authentication authentication, HttpServletRequest request, Object targetObject);
}
