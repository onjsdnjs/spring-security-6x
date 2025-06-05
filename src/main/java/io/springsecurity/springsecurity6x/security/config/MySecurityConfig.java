package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.method.CustomMethodSecurityExpressionHandler;
import io.springsecurity.springsecurity6x.security.permission.CustomPermissionEvaluator;
import io.springsecurity.springsecurity6x.service.MethodResourceService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class MySecurityConfig {

    private final MethodResourceService methodResourceService; // MethodResourceService 주입

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * ModelMapper bean
     */
    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    // CustomMethodSecurityExpressionHandler 빈 등록
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(CustomPermissionEvaluator customPermissionEvaluator, RoleHierarchy roleHierarchy ) {
        // CustomMethodSecurityExpressionHandler의 생성자에 필요한 모든 의존성을 주입
        // 이 핸들러가 DB에서 MethodResource를 로드하는 로직을 포함합니다.
        CustomMethodSecurityExpressionHandler expressionHandler =
                new CustomMethodSecurityExpressionHandler(methodResourceService, customPermissionEvaluator, roleHierarchy);
        return expressionHandler;
    }

    // RoleHierarchy 빈 등록 (계층적 역할 지원)
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // 여기에서 DB에서 로드한 역할 계층 정보를 설정할 수 있습니다.
        // 예: "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER"
        // 초기에는 하드코딩으로 설정하고, 나중에 DB에서 동적으로 로드하도록 확장 가능합니다.
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER");
        return roleHierarchy;
    }

}
