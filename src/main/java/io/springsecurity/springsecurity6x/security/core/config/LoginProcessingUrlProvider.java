package io.springsecurity.springsecurity6x.security.core.config;

/**
 * 각 인증 옵션이 로그인 처리 URL을 제공하도록 하는 공통 인터페이스
 */
public interface LoginProcessingUrlProvider {
    /**
     * POST 로그인 처리 URL (예: "/login/form", "/login/ott" 등)
     */
    String getLoginProcessingUrl();
}
