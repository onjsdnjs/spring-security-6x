package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes; // ASEP 속성이 필요하면 구체적인 타입으로 변경 (예: RestAsepAttributes)
import io.springsecurity.springsecurity6x.security.core.dsl.option.RecoveryCodeOptions;

public interface RecoveryCodeDslConfigurer extends AuthenticationFactorConfigurer<RecoveryCodeOptions, BaseAsepAttributes, RecoveryCodeDslConfigurer>  {
    RecoveryCodeDslConfigurer codeLength(int length);
    RecoveryCodeDslConfigurer numberOfCodesToGenerate(int number);
    RecoveryCodeDslConfigurer emailOtpEndpoint(String endpoint); // 추가
    RecoveryCodeDslConfigurer smsOtpEndpoint(String endpoint);   // 추가
    // order()는 AuthenticationFactorConfigurer에 이미 있음
}