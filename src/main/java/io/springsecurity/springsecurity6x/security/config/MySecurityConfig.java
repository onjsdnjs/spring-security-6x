package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.admin.service.DocumentService;
import io.springsecurity.springsecurity6x.admin.service.impl.RoleHierarchyService;
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
    private final DocumentService documentService;
    private final RoleHierarchyService roleHierarchyService;

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
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            CustomPermissionEvaluator customPermissionEvaluator,
            RoleHierarchy roleHierarchy,
            MethodResourceService methodResourceService
    ) {
        return new CustomMethodSecurityExpressionHandler(methodResourceService, customPermissionEvaluator, roleHierarchy);
    }

    // CustomPermissionEvaluator 빈
    @Bean
    public CustomPermissionEvaluator customPermissionEvaluator(PermissionRepository permissionRepository, DocumentService documentService) {
        return new CustomPermissionEvaluator(permissionRepository, documentService);
    }

    // RoleHierarchy 빈 등록 (계층적 역할 지원)
    // 애플리케이션 시작 시 RoleHierarchyService를 통해 DB에서 계층 정보를 로드하여 설정합니다.
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // 애플리케이션 시작 시 RoleHierarchyService를 통해 최신 계층 정보를 로드하여 설정
        // 이 시점에는 아직 RoleHierarchyService의 @PostConstruct가 호출되지 않았을 수 있으므로,
        // RoleHierarchyService 내부에서 ApplicationContext를 주입받아 setHierarchy를 호출하는 방식이 더 안전합니다.
        // 또는 RoleHierarchyService의 reloadRoleHierarchyBean()을 명시적으로 호출합니다.
        // 여기서는 RoleHierarchyService가 빈으로 주입되고, 그 서비스의 메서드가 호출될 때 계층이 설정된다고 가정합니다.
        // Spring이 빈 의존성을 해결하는 순서 때문에 복잡해질 수 있습니다.
        // 간단하게는, RoleHierarchyService의 init() 또는 @PostConstruct 메서드에서
        // applicationRoleHierarchy.setHierarchy()를 호출하도록 합니다.
        // PlatformSecurityConfig의 생성자가 실행될 때 RoleHierarchyService는 이미 생성되어 있습니다.
        roleHierarchyService.reloadRoleHierarchyBean(); // 애플리케이션 시작 시 DB 에서 계층 로드 및 설정
        return roleHierarchy;
    }

}
