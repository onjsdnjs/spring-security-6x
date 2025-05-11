package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

/**
 * 재시도 정책 데이터 객체
 */
public record RetryPolicy(int maxAttempts, long lockoutSec) {
}
