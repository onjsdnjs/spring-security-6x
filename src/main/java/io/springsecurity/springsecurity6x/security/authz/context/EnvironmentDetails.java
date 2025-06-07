package io.springsecurity.springsecurity6x.security.authz.context;

import java.time.LocalDateTime;

/**
 * 요청 환경(Environment)의 상세 정보를 담는 객체.
 */
public record EnvironmentDetails(
        String remoteIp,
        LocalDateTime timestamp) {}
