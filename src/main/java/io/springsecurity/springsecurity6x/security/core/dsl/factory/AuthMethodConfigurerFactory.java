package io.springsecurity.springsecurity6x.security.core.dsl.factory;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*; // 모든 Configurer 인터페이스
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.*; // 모든 Configurer 구현체
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.extern.slf4j.Slf4j; // 로깅 추가
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer; // AbstractHttpConfigurer 사용

import java.util.Objects;

@Slf4j // 로깅 추가
public final class AuthMethodConfigurerFactory { // final class

    private final ApplicationContext applicationContext;

    public AuthMethodConfigurerFactory(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
    }

    /**
     * 지정된 AuthType에 맞는 DSL Configurer 인스턴스를 생성하고 HttpSecurityBuilder를 설정합니다.
     *
     * @param authType 생성할 Configurer의 인증 타입
     * @param builder  Configurer가 적용될 HttpSecurityBuilder (non-null)
     * @param <H>      HttpSecurityBuilder의 구체적인 타입
     * @param <O>      해당 Configurer가 사용하는 Options 타입
     * @param <A>      해당 Configurer가 사용하는 ASEP Attributes 타입
     * @param <S>      반환될 Configurer의 인터페이스 타입 (자기 자신을 Self 타입으로 가짐)
     * @param <Impl>   실제 생성될 Configurer의 구현체 타입 (S를 구현하고 AbstractHttpConfigurer를 상속)
     * @param configurerInterfaceType Configurer의 인터페이스 타입 (타입 안전한 반환용)
     * @return 구성된 Configurer 인스턴스
     * @throws IllegalArgumentException 지원하지 않는 authType인 경우
     * @throws RuntimeException Configurer에 HttpSecurityBuilder를 적용(apply)하는 중 오류 발생 시
     */
    public <H extends HttpSecurityBuilder<H>,
            O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            S extends AuthenticationFactorConfigurer<O, A, S>,
            Impl extends AbstractHttpConfigurer<Impl, H>> // Configurer 구현체 (Spring의 AbstractHttpConfigurer 상속 및 S 인터페이스 구현)
    S createFactorConfigurer(AuthType authType, H builder, Class<S> configurerInterfaceType) {
        Objects.requireNonNull(authType, "AuthType cannot be null");
        Objects.requireNonNull(builder, "HttpSecurityBuilder cannot be null");
        Objects.requireNonNull(configurerInterfaceType, "ConfigurerInterfaceType cannot be null");

        AbstractHttpConfigurer<?, H> concreteConfigurer = switch (authType) {

            case FORM -> {
                FormDslConfigurerImpl<H> configurer = new FormDslConfigurerImpl<>();
                configurer.setApplicationContext(this.applicationContext);
                yield configurer;
            }
            case REST -> {
                RestDslConfigurerImpl<H> configurer = new RestDslConfigurerImpl<>();
                configurer.setApplicationContext(this.applicationContext);
                yield configurer;
            }
            case OTT -> {
                // OttDslConfigurerImpl은 생성자에서 ApplicationContext를 받음 (제공된 코드 기준)
                OttDslConfigurerImpl<H> configurer = new OttDslConfigurerImpl<>(this.applicationContext);
                yield configurer;
            }
            case PASSKEY -> {
                PasskeyDslConfigurerImpl<H> configurer = new PasskeyDslConfigurerImpl<>();
                configurer.setApplicationContext(this.applicationContext);
                yield configurer;
            }
            // case RECOVERY_CODE -> {
            //    RecoveryCodeDslConfigurerImpl<H> configurer = new RecoveryCodeDslConfigurerImpl<>();
            //    configurer.setApplicationContext(this.applicationContext);
            //    yield configurer;
            // }
            default -> {
                log.error("AuthMethodConfigurerFactory: Unsupported AuthType for AuthenticationFactorConfigurer: {}", authType);
                throw new IllegalArgumentException("Unsupported AuthType for AuthenticationFactorConfigurer: " + authType);
            }
        };

        // 반환 타입 C (호출자가 기대하는 인터페이스 타입)로 안전하게 캐스팅
        if (configurerInterfaceType.isInstance(concreteConfigurer)) {
            return configurerInterfaceType.cast(concreteConfigurer);
        } else {
            // 이 경우는 제네릭 타입 약속 위반 또는 내부 로직 오류
            log.error("AuthMethodConfigurerFactory: Created configurer of type {} is not assignable to expected interface {}.",
                    concreteConfigurer.getClass().getSimpleName(), configurerInterfaceType.getSimpleName());
            throw new IllegalArgumentException("Created configurer type mismatch. Expected: " +
                    configurerInterfaceType.getSimpleName() + ", Actual: " + concreteConfigurer.getClass().getSimpleName());
        }
    }

    /**
     * PrimaryAuthDslConfigurer 인스턴스를 생성합니다.
     * 이 Configurer는 AbstractHttpConfigurer를 상속하지 않으므로 별도 처리합니다.
     */
    public <H extends HttpSecurityBuilder<H>> PrimaryAuthDslConfigurerImpl<H> createPrimaryAuthConfigurer(H httpSecurityBuilder) {
        Objects.requireNonNull(httpSecurityBuilder, "HttpSecurityBuilder cannot be null for PrimaryAuthDslConfigurer");
        return new PrimaryAuthDslConfigurerImpl<>(this.applicationContext, httpSecurityBuilder);
    }

    /**
     * MfaDslConfigurer 인스턴스를 생성하고 HttpSecurityBuilder에 apply합니다.
     */
    public <H extends HttpSecurityBuilder<H>> MfaDslConfigurerImpl<H> createAndApplyMfaConfigurer(H builder) {
        Objects.requireNonNull(builder, "HttpSecurityBuilder cannot be null for MfaDslConfigurer");
        return new MfaDslConfigurerImpl<>(this.applicationContext);
    }
}