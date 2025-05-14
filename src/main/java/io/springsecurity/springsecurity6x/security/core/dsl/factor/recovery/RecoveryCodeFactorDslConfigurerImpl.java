package io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery;

import io.springsecurity.springsecurity6x.security.core.mfa.options.recovery.RecoveryCodeFactorOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

public class RecoveryCodeFactorDslConfigurerImpl implements RecoveryCodeFactorDslConfigurer {
    private final RecoveryCodeFactorOptions options = new RecoveryCodeFactorOptions();

    public RecoveryCodeFactorDslConfigurerImpl() {
        // 기본값 설정
    }

    @Override
    public RecoveryCodeFactorDslConfigurer processingUrl(String url) {
        this.options.setProcessingUrl(url);
        return this;
    }

    @Override
    public RecoveryCodeFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.options.setSuccessHandler(handler);
        return this;
    }

    @Override
    public RecoveryCodeFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.options.setFailureHandler(handler);
        return this;
    }

    /*
    @Override
    public RecoveryCodeFactorDslConfigurer recoveryCodeStore(RecoveryCodeStore recoveryCodeStore) {
        this.options.setRecoveryCodeStore(recoveryCodeStore);
        return this;
    }

    @Override
    public RecoveryCodeFactorDslConfigurer recoveryCodeStoreBeanName(String beanName) {
        // ApplicationContext 주입받아 빈 조회 로직 추가
        return this;
    }
    */

    @Override
    public RecoveryCodeFactorDslConfigurer codeLength(int length) {
        Assert.isTrue(length > 0, "Code length must be positive.");
        this.options.setCodeLength(length);
        return this;
    }

    @Override
    public RecoveryCodeFactorDslConfigurer numberOfCodesToGenerate(int number) {
        Assert.isTrue(number > 0, "Number of codes to generate must be positive.");
        this.options.setNumberOfCodesToGenerate(number);
        return this;
    }

    @Override
    public RecoveryCodeFactorOptions buildAuthenticationOptions() {
        Assert.hasText(options.getProcessingUrl(), "Processing URL must be set for Recovery Code factor.");
        // Assert.notNull(options.getRecoveryCodeStore(), "RecoveryCodeStore must be configured for Recovery Code factor.");
        return this.options;
    }
}