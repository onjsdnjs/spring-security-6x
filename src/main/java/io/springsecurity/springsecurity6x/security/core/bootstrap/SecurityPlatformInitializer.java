package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityPlatform 구현체
 * - DSL, AuthenticationFeature, StateFeature를 결합해 SecurityFilterChain을 빌드
 */
@Slf4j
public class SecurityPlatformInitializer implements SecurityPlatform {
    private final PlatformContext context;
    private final List<SecurityConfigurer> configurers;  // Flow, Global 등 기본 설정
    private final FeatureRegistry featureRegistry;              // 인증/상태 Feature 레지스트리
    private PlatformConfig config;

    /**
     * @param context          플랫폼 컨텍스트
     * @param configurers 기본 Configurer 리스트 (FlowConfigurer, GlobalConfigurer)
     * @param featureRegistry   FeatureRegistry
     */
    public SecurityPlatformInitializer(
            PlatformContext context,
            List<SecurityConfigurer> configurers,
            FeatureRegistry featureRegistry) {
        this.context = context;
        this.configurers = configurers;
        this.featureRegistry = featureRegistry;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    /**
     * 1) FlowContext 생성 및 정렬
     * 2) Configurer 조합
     * 3) init/configure 단계 실행
     * 4) SecurityFilterChain 등록
     */
    @Override
    public void initialize() {
        List<FlowContext> flows = createAndSortFlows();
        List<SecurityConfigurer> configurers = buildConfigurers();

        initConfigurers(configurers);
        configureFlows(configurers, flows);
        registerSecurityFilterChains(flows);
    }

    // FlowContext 생성 및 DSL .order() 기준 정렬
    private List<FlowContext> createAndSortFlows() {
        List<FlowContext> flows = new ArrayList<>();
        for (AuthenticationFlowConfig flow : config.flows()) {
            try {

                HttpSecurity http = context.newHttp();
                context.registerHttp(flow, http);
                FlowContext fc = new FlowContext(flow, http, context, config);
                context.share(FlowContext.class, fc);
                flows.add(fc);

            } catch (Exception ex) {
                log.error("FlowContext 생성 실패: {}", flow.typeName(), ex);
            }
        }
        flows.sort(Comparator.comparingInt(fc -> fc.flow().order()));
        return flows;
    }

    private List<SecurityConfigurer> buildConfigurers() {

        List<SecurityConfigurer> list = new ArrayList<>(configurers);

        featureRegistry.getAuthFeaturesFor(config.flows())
                .forEach(f -> list.add(new AuthFeatureConfigurerAdapter(f)));

        featureRegistry.getStateFeaturesFor(config.flows())
                .forEach(sf -> list.add(new StateFeatureConfigurerAdapter(sf, context)));

        return list;
    }

    // init 단계: init(context, config) 호출
    private void initConfigurers(List<SecurityConfigurer> configurers) {
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    try { cfg.init(context, config); }
                    catch (Exception e) {
                        throw new IllegalStateException("Configurer init 실패: " + cfg, e);
                    }
                });
    }

    // configure 단계: configure(FlowContext) 호출
    private void configureFlows(List<SecurityConfigurer> configurers, List<FlowContext> flows) {
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    for (FlowContext fc : flows) {
                        try { cfg.configure(fc); }
                        catch (Exception e) {
                            throw new IllegalStateException("Configurer configure 실패: " + cfg, e);
                        }
                    }
                });
    }

    // FlowContext별 SecurityFilterChain 빌드 및 Bean 등록
    private void registerSecurityFilterChains(List<FlowContext> flows) {
        ConfigurableApplicationContext cac = (ConfigurableApplicationContext) context.applicationContext();
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger chainOrder = new AtomicInteger(1);

        for (FlowContext fc : flows) {
            String flowName = fc.flow().typeName();
            int orderVal = fc.flow().order();
            String beanName = flowName + "SecurityFilterChain" + chainOrder.getAndIncrement();
            BeanDefinitionBuilder builder = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class, () -> {
                        try {
                            DefaultSecurityFilterChain built = fc.http().build();

                            for (AuthenticationStepConfig step : fc.flow().stepConfigs()) {
                                String type = step.type();
                                Filter factorFilter = built.getFilters().stream()
                                        .filter(f -> {
                                            switch (type) {
                                                case "form":
                                                    return f instanceof UsernamePasswordAuthenticationFilter;
                                                case "rest":
                                                    return f.getClass().getSimpleName()
                                                            .equals("RestAuthenticationFilter");
                                                case "ott":
                                                    return f.getClass().getSimpleName()
                                                            .equals("OneTimeTokenAuthenticationFilter");
                                                case "passkey":
                                                    return f.getClass().getSimpleName()
                                                            .equals("WebAuthnAuthenticationFilter");
                                                default:
                                                    return false;
                                            }
                                        })
                                        .findFirst()
                                        .orElseThrow(() -> new IllegalStateException(
                                                "필터를 찾을 수 없습니다 for MFA 타입: " + type));

                                featureRegistry.registerFactorFilter(type, factorFilter);
                            }

                            return new OrderedSecurityFilterChain(
                                    Ordered.HIGHEST_PRECEDENCE + orderVal,
                                    built.getRequestMatcher(),
                                    built.getFilters());
                        } catch (Exception ex) {
                            log.error("SecurityFilterChain 생성 실패 (flow={}): 건너뜁니다.", flowName, ex);
                            throw new BeanCreationException(
                                    "SecurityFilterChain 생성 실패 for flow: " + flowName, ex);
                        }
                    });
            builder.setLazyInit(true);
            builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
        }
    }
}

