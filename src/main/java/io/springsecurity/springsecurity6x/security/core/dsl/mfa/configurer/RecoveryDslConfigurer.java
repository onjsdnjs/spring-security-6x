package io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.mfa.RecoveryConfig;

public interface RecoveryDslConfigurer {
    /**
     * 이메일 OTP 복구 흐름 엔드포인트 설정
     */
    RecoveryDslConfigurer emailOtpEndpoint(String endpoint);

    /**
     * SMS OTP 복구 흐름 엔드포인트 설정
     */
    RecoveryDslConfigurer smsOtpEndpoint(String endpoint);

    /**
     * RecoveryConfig 빌드
     */
    RecoveryConfig build();
}

