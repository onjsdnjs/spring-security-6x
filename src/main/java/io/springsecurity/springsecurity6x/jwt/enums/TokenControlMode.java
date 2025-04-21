package io.springsecurity.springsecurity6x.jwt.enums;

public enum TokenControlMode {
    EXTERNAL,  // 우리가 직접 필터, DSL로 토큰 발급/검증
    INTERNAL   // OAuth2 Resource Server 자동 처리 방식
}
