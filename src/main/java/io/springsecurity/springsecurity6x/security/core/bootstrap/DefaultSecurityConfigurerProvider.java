package io.springsecurity.springsecurity6x.security.core.bootstrap;


import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * SecurityConfigurer 인스턴스 목록을 제공하는 기본 구현체입니다.
 * 이 클래스는 다양한 유형의 SecurityConfigurer (예: 기본, DSL 기반, Feature 기반)를 생성하고 반환합니다.
 */
@Component // Spring 컴포넌트로 등록할 경우
public class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> baseConfigurers;
    private final FeatureRegistry featureRegistry;

    /**
     * DefaultSecurityConfigurerProvider 생성자.
     *
     * @param baseConfigurers   애플리케이션에 기본적으로 적용될 SecurityConfigurer 목록 (예: FlowConfigurer, GlobalConfigurer).
     * Spring 환경에서는 @Autowired를 통해 주입받거나, 직접 생성하여 전달할 수 있습니다.
     * @param featureRegistry   인증 및 상태 기능을 조회하기 위한 레지스트리.
     */
    @Autowired // Spring을 사용하는 경우, baseConfigurers는 List<SecurityConfigurer> 타입의 모든 빈을 주입받을 수 있습니다.
    public DefaultSecurityConfigurerProvider(List<SecurityConfigurer> baseConfigurers,
                                             FeatureRegistry featureRegistry) {
        // baseConfigurers 에는 FlowConfigurer, GlobalConfigurer 등이 주입될 수 있습니다.
        // 만약 baseConfigurers를 외부에서 주입받지 않고 내부에서 생성하려면 아래와 같이 할 수 있습니다.
        // this.baseConfigurers = List.of(new FlowConfigurer(), new GlobalConfigurer());
        this.baseConfigurers = new ArrayList<>(baseConfigurers); // 주입받은 리스트를 복사하여 사용
        this.featureRegistry = featureRegistry;
    }

    /**
     * 주어진 컨텍스트와 설정을 기반으로 적용할 모든 SecurityConfigurer 목록을 생성하여 반환합니다.
     *
     * @param platformContext 플랫폼 전역 컨텍스트
     * @param platformConfig  플랫폼 전역 설정
     * @return 구성된 SecurityConfigurer 목록
     */
    @Override
    public List<SecurityConfigurer> getConfigurers(PlatformContext platformContext,
                                                   PlatformConfig platformConfig) {

        List<SecurityConfigurer> configurers = new ArrayList<>(this.baseConfigurers);
        // 2. AuthenticationFeature 기반 Configurer 추가
        featureRegistry.getAuthFeaturesFor(platformConfig.flows())
                .forEach(feature -> configurers.add(new AuthFeatureConfigurerAdapter(feature)));

        // 3. StateFeature 기반 Configurer 추가
        featureRegistry.getStateFeaturesFor(platformConfig.flows())
                .forEach(stateFeature -> configurers.add(new StateFeatureConfigurerAdapter(stateFeature, platformContext)));

        // 필요에 따라 다른 유형의 SecurityConfigurer를 동적으로 추가할 수 있습니다.

        return configurers;
    }
}
