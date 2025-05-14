package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.StepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import java.util.Objects;

// OBI는 OptionsBuilderDsl을 구현하는 구체적인 OptionsBuilderConfigurer 타입이어야 함
// S는 StepDslConfigurer를 구현하는 구체적인 StepAware Configurer 인터페이스 타입이어야 함
public abstract class AbstractStepAwareDslConfigurer<
        O extends AbstractOptions, // 최종 빌드될 Options 타입
        B extends AbstractOptions.Builder<O, B>, // Options의 Builder 타입
        OBI extends AbstractOptionsBuilderConfigurer<O, B, ? extends OptionsBuilderDsl<O, ?>>, // Options 빌딩을 담당하는 Configurer의 구현체
        S extends StepDslConfigurer // 이 Configurer의 Self-type (예: FormStepDslConfigurer)
        > implements StepDslConfigurer {

    private final AuthenticationStepConfig stepConfig;
    protected final OBI optionsConfigurerImpl; // Options 빌딩 로직을 위임받을 구현체

    protected AbstractStepAwareDslConfigurer(AuthenticationStepConfig stepConfig, OBI optionsConfigurerImpl) {
        this.stepConfig = Objects.requireNonNull(stepConfig, "stepConfig cannot be null for a StepAwareDslConfigurer");
        this.optionsConfigurerImpl = Objects.requireNonNull(optionsConfigurerImpl, "optionsConfigurerImpl cannot be null");
        // 기본 order 설정은 stepConfig 자체의 초기값 또는 생성 시 설정
        // this.stepConfig.setOrder(optionsConfigurerImpl.hashCode()); // 이 로직은 적절치 않을 수 있음
    }

    protected AuthenticationStepConfig getStepConfig() {
        return stepConfig;
    }

    // order 설정을 위한 메소드. 반환 타입을 S로 변경.
    // 이 메소드는 StepDslConfigurer 인터페이스에 포함되지 않으므로, 각 구체적인 Step-aware DSL 인터페이스에 추가 필요.
    // (예: FormStepDslConfigurer에 FormStepDslConfigurer order(int orderValue); 추가)
    // 여기서는 구현의 편의를 위해 public으로 두지만, 인터페이스에 정의하는 것이 더 명확합니다.
    public S order(int orderValue) {
        this.stepConfig.setOrder(orderValue);
        return self();
    }

    @Override
    public int getOrder() {
        return this.stepConfig.getOrder();
    }

    @Override
    public AuthenticationStepConfig toConfig() {
        O options = this.optionsConfigurerImpl.buildConcreteOptions();
        // AuthenticationStepConfig에 옵션을 추가하는 표준화된 방법 필요
        // 예를 들어, AuthenticationStepConfig에 Map<String, Object> options 필드가 있고,
        // 여기에 "_options" 키로 저장한다고 가정합니다.
        this.stepConfig.getOptions().put("_options", options); // getOptions()가 Map을 반환한다고 가정
        this.stepConfig.setType(getAuthTypeName());
        return this.stepConfig;
    }

    /**
     * 이 Configurer가 나타내는 인증 타입의 이름을 반환합니다 (예: "form", "rest").
     * @return 인증 타입 이름
     */
    protected abstract String getAuthTypeName();

    /**
     * 현재 Configurer 인스턴스(Self-type)를 반환합니다. 하위 클래스에서 반드시 구현해야 합니다.
     * @return this (Self-type S)
     */
    protected abstract S self();
}
