package io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer; // OptionsBuilderDsl 사용 위해 추가
import io.springsecurity.springsecurity6x.security.core.mfa.options.recovery.RecoveryCodeFactorOptions;
import org.springframework.security.config.Customizer; // 추가
import org.springframework.security.config.annotation.web.builders.HttpSecurity; // 추가
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer; // 추가
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer; // 추가
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer; // 추가
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer; // 추가
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

public class RecoveryCodeFactorDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<RecoveryCodeFactorOptions, RecoveryCodeFactorOptions.Builder, RecoveryCodeFactorDslConfigurer>
        implements RecoveryCodeFactorDslConfigurer {

    public RecoveryCodeFactorDslConfigurerImpl() {
        super(RecoveryCodeFactorOptions.builder());
    }

    @Override
    protected RecoveryCodeFactorDslConfigurer self() {
        return this;
    }

    // --- RecoveryCodeFactorDslConfigurer 고유 메소드 구현 ---
    @Override
    public RecoveryCodeFactorDslConfigurer codeLength(int length) {
        Assert.isTrue(length > 0, "Code length must be positive.");
        this.optionsBuilder.codeLength(length); // optionsBuilder를 통해 설정
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer numberOfCodesToGenerate(int number) {
        Assert.isTrue(number > 0, "Number of codes to generate must be positive.");
        this.optionsBuilder.numberOfCodesToGenerate(number); // optionsBuilder를 통해 설정
        return self();
    }

    /* 주석 처리된 recoveryCodeStore 관련 메소드는 RecoveryCodeFactorDslConfigurer 인터페이스에도 없다고 가정
    @Override
    public RecoveryCodeFactorDslConfigurer recoveryCodeStore(RecoveryCodeStore recoveryCodeStore) {
        this.optionsBuilder.recoveryCodeStore(recoveryCodeStore); // optionsBuilder를 통해 설정
        return this;
    }

    @Override
    public RecoveryCodeFactorDslConfigurer recoveryCodeStoreBeanName(String beanName) {
        // ApplicationContext 주입받아 빈 조회 로직 추가 (팩토리에서 처리하거나, 이 클래스 생성자에 Context 주입)
        // RecoveryCodeStore store = applicationContext.getBean(beanName, RecoveryCodeStore.class);
        // this.optionsBuilder.recoveryCodeStore(store);
        return this;
    }
    */

    // --- FactorDslConfigurer (OptionsBuilderDsl의 일부) 공통 메소드 구현 ---
    // 이 메소드들은 RecoveryCodeFactorDslConfigurer 인터페이스에 선언되어 있어야 함
    @Override
    public RecoveryCodeFactorDslConfigurer processingUrl(String url) {
        this.optionsBuilder.processingUrl(url); // optionsBuilder를 통해 설정
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); // optionsBuilder를 통해 설정
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); // optionsBuilder를 통해 설정
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        super.rawHttp(customizer);
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer disableCsrf() {
        super.disableCsrf();
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        super.cors(customizer);
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        super.headers(customizer);
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        super.sessionManagement(customizer);
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        super.logout(customizer);
        return self();
    }

}