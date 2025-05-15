package io.springsecurity.springsecurity6x.security.core.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.options.RecoveryCodeFactorOptions;

public interface RecoveryDslConfigurer extends OptionsBuilderDsl<RecoveryCodeFactorOptions, RecoveryDslConfigurer> {
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

