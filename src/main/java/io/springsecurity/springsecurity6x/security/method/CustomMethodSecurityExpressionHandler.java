package io.springsecurity.springsecurity6x.security.method;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import io.springsecurity.springsecurity6x.security.permission.CustomPermissionEvaluator;
import io.springsecurity.springsecurity6x.service.MethodResourceService;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.lang.reflect.Method;
import java.util.Optional;

@Slf4j
public class CustomMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    private final MethodResourceService methodResourceService;
    private final CustomPermissionEvaluator customPermissionEvaluator;
    private RoleHierarchy roleHierarchy; // RoleHierarchy는 setRoleHierarchy를 통해 설정됨

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public CustomMethodSecurityExpressionHandler(MethodResourceService methodResourceService,
                                                 CustomPermissionEvaluator customPermissionEvaluator,
                                                 RoleHierarchy roleHierarchy) { // 생성자 주입
        Assert.notNull(methodResourceService, "MethodResourceService cannot be null");
        Assert.notNull(customPermissionEvaluator, "CustomPermissionEvaluator cannot be null");
        Assert.notNull(roleHierarchy, "RoleHierarchy cannot be null"); // RoleHierarchy도 필수 주입

        this.methodResourceService = methodResourceService;
        this.customPermissionEvaluator = customPermissionEvaluator;
        this.roleHierarchy = roleHierarchy;

        // 부모 클래스의 메서드를 통해 의존성 등록
        super.setPermissionEvaluator(this.customPermissionEvaluator);
        super.setRoleHierarchy(this.roleHierarchy);

        log.info("CustomMethodSecurityExpressionHandler initialized. Using MethodResourceService for dynamic lookup.");
    }

    // RoleHierarchy를 직접 설정할 수 있도록 오버라이드 (선택 사항, 빈 주입으로도 가능)
    @Override
    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        super.setRoleHierarchy(roleHierarchy);
        this.roleHierarchy = roleHierarchy;
    }

    // AuthenticationTrustResolver를 직접 설정할 수 있도록 오버라이드 (선택 사항)
    @Override
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        super.setTrustResolver(trustResolver);
        this.trustResolver = trustResolver;
    }

    /**
     * SpEL 표현식을 평가할 EvaluationContext를 생성합니다.
     * 이 메서드에서 DB에서 동적으로 로드된 MethodResource의 accessExpression을 통합합니다.
     *
     * @param authentication 현재 인증된 사용자 정보
     * @param mi 호출되는 메서드에 대한 정보 (MethodInvocation)
     * @return 커스터마이징된 EvaluationContext
     */
    @Override
    public EvaluationContext createEvaluationContext(Authentication authentication, MethodInvocation mi) {
        // 부모 클래스(DefaultMethodSecurityExpressionHandler)가 생성하는 기본 컨텍스트
        // 이 컨텍스트의 Root Object는 MethodSecurityExpressionRoot 입니다.
        StandardEvaluationContext ctx = (StandardEvaluationContext) super.createEvaluationContext(authentication, mi);

        // 1. 메서드 호출 정보 추출
        Method method = mi.getMethod();
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        // 실제 HttpMethod를 얻는 것은 HttpServletRequest에서 해야 하지만, MethodSecurityExpressionHandler는 Request에 직접 접근 불가
        // 따라서, @PreAuthorize의 인자로 HttpMethod를 넘기거나, MethodResource에 HttpMethod가 'ALL'로 되어있다고 가정합니다.
        // 여기서는 MethodResourceService의 findByClassNameAndMethodNameAndHttpMethod를 위해 "ALL"을 기본으로 사용합니다.
        String httpMethod = "ALL"; // 또는 RequestContextHolder를 통해 HttpServletRequest에서 추출 (더 복잡)

        // 2. DB에서 MethodResource 조회
        // DB에 여러 HTTP 메서드가 등록될 수 있으므로, 가장 구체적인 것을 먼저 찾고, 없으면 ALL을 찾도록 로직을 추가할 수 있습니다.
        Optional<MethodResource> methodResourceOpt = methodResourceService.getMethodResourceBySignature(className, methodName, httpMethod);

        if (methodResourceOpt.isEmpty()) {
            // 특정 HTTP 메서드로 찾지 못했다면, 'ALL' HTTP 메서드를 가진 것을 찾아봅니다.
            methodResourceOpt = methodResourceService.getMethodResourceBySignature(className, methodName, "ALL");
        }


        // 3. CustomMethodSecurityExpressionRoot 생성 및 설정
        // DB에서 동적으로 로드된 accessExpression을 평가할 수 있는 커스텀 Root 객체를 사용합니다.
        CustomMethodSecurityExpressionRoot customRoot;

        if (methodResourceOpt.isPresent()) {
            MethodResource methodResource = methodResourceOpt.get();
            String dbAccessExpressionString = methodResource.getAccessExpression();
            log.debug("Dynamic method resource found: {}.{} with expression: '{}' (ID: {})",
                    className, methodName, dbAccessExpressionString, methodResource.getId());

            // DB에서 가져온 SpEL 표현식을 Expression 객체로 파싱
            Expression parsedDbExpression = getExpressionParser().parseExpression(dbAccessExpressionString);

            customRoot = new CustomMethodSecurityExpressionRoot(authentication, mi, parsedDbExpression);

            // DB에서 로드된 역할 및 권한 정보를 SpEL 컨텍스트에 추가하여 SpEL 표현식에서 참조 가능하도록 합니다.
            // (예: #root.dbRoles, #root.dbPermissions)
            // CustomMethodSecurityExpressionRoot 클래스에 이 정보를 담는 필드와 getter를 추가합니다.
            customRoot.setDbMethodResource(methodResource);

        } else {
            log.debug("No dynamic method resource found for {}.{}.{} Using default static security if any.", className, methodName, httpMethod);
            // DB에 매핑된 메서드 리소스가 없으면, `@PreAuthorize` 어노테이션에 직접 정의된 표현식이 평가됩니다.
            customRoot = new CustomMethodSecurityExpressionRoot(authentication, mi, null); // 동적 표현식 없음
        }

        // CustomMethodSecurityExpressionRoot에 필요한 의존성 주입 (부모 클래스 필드 활용)
        customRoot.setPermissionEvaluator(getPermissionEvaluator());
        customRoot.setTrustResolver(this.trustResolver);
        customRoot.setRoleHierarchy(this.roleHierarchy);
        customRoot.setThis(mi.getThis()); // Spring Security의 setThis() 호출

        ctx.setRootObject(customRoot); // 생성된 CustomMethodSecurityExpressionRoot를 Root Object로 설정

        return ctx;
    }
}
