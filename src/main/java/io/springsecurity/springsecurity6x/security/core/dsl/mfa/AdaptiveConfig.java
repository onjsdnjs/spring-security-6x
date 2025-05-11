package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

/**
 * Adaptive 정책 도메인 객체
 */
public record AdaptiveConfig(boolean geolocation, boolean devicePosture) {
}
