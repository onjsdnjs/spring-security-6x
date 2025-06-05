package io.springsecurity.springsecurity6x.security.method;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import io.springsecurity.springsecurity6x.security.permission.CustomPermissionEvaluator;
import io.springsecurity.springsecurity6x.service.MethodResourceService;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication; // Authentication 임포트
import org.springframework.expression.EvaluationContext; // EvaluationContext 임포트
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.util.Assert;

import java.lang.reflect.Method;
import java.util.Optional;
import java.util.function.Supplier; // <<< Supplier 임포트 추가

@Slf4j
public class CustomMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    private final MethodResourceService methodResourceService;
    private final CustomPermissionEvaluator customPermissionEvaluator;
    private RoleHierarchy roleHierarchy;

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public CustomMethodSecurityExpressionHandler(MethodResourceService methodResourceService,
                                                 CustomPermissionEvaluator customPermissionEvaluator,
                                                 RoleHierarchy roleHierarchy) {
        Assert.notNull(methodResourceService, "MethodResourceService cannot be null");
        Assert.notNull(customPermissionEvaluator, "CustomPermissionEvaluator cannot be null");
        Assert.notNull(roleHierarchy, "RoleHierarchy cannot be null");

        this.methodResourceService = methodResourceService;
        this.customPermissionEvaluator = customPermissionEvaluator;
        this.roleHierarchy = roleHierarchy;

        super.setPermissionEvaluator(this.customPermissionEvaluator);
        super.setRoleHierarchy(this.roleHierarchy);
        super.setTrustResolver(this.trustResolver);

        log.info("CustomMethodSecurityExpressionHandler initialized. Using MethodResourceService for dynamic lookup.");
    }

    @Override
    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        super.setRoleHierarchy(roleHierarchy);
        this.roleHierarchy = roleHierarchy;
    }

    @Override
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        super.setTrustResolver(trustResolver);
        this.trustResolver = trustResolver;
    }

    /**
     * SpEL 표현식 평가를 위한 EvaluationContext를 생성합니다.
     * 이 메서드에서 DB에서 동적으로 로드된 MethodResource의 accessExpression을 통합합니다.
     *
     * @param authentication 현재 인증된 사용자 정보를 제공하는 Supplier
     * @param mi 호출되는 메서드에 대한 정보 (MethodInvocation)
     * @return 커스터마이징된 EvaluationContext
     */
    @Override
    public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) { // <<< Supplier<Authentication>으로 변경
        // 부모 클래스(DefaultMethodSecurityExpressionHandler)의 createEvaluationContext를 호출하여
        // 기본 StandardEvaluationContext와 그 안에 설정된 MethodSecurityExpressionRoot를 가져옵니다.
        StandardEvaluationContext ctx = (StandardEvaluationContext) super.createEvaluationContext(authentication, mi);

        // 1. 메서드 호출 정보 추출
        Method method = mi.getMethod();
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        String httpMethod = "ALL"; // MethodSecurity는 HttpMethod를 직접 알 수 없음. DB 조회용.

        // 2. DB에서 MethodResource 조회
        Optional<MethodResource> methodResourceOpt = methodResourceService.getMethodResourceBySignature(className, methodName, httpMethod);
        if (methodResourceOpt.isEmpty()) {
            methodResourceOpt = methodResourceService.getMethodResourceBySignature(className, methodName, "ALL");
        }

        if (methodResourceOpt.isPresent()) {
            MethodResource methodResource = methodResourceOpt.get();
            String dbAccessExpressionString = methodResource.getAccessExpression();
            log.debug("Dynamic method resource found: {}.{} with expression: '{}' (ID: {})",
                    className, methodName, dbAccessExpressionString, methodResource.getId());

            // 3. DB에서 가져온 SpEL 표현식을 Expression 객체로 파싱
            Expression parsedDbExpression = getExpressionParser().parseExpression(dbAccessExpressionString);

            // 4. 파싱된 Expression을 EvaluationContext에 변수로 등록합니다.
            //    SpEL 표현식에서 #dynamicAccessRule.getValue(#root) 와 같이 접근할 수 있습니다.
            ctx.setVariable("dynamicAccessRule", parsedDbExpression);
            // 필요시 DB에서 로드된 MethodResource 엔티티 자체도 변수로 등록 가능 (#dbMethodResource)
            ctx.setVariable("dbMethodResource", methodResource);

            // 중요: @PreAuthorize("#dynamicAccessRule.getValue(#root)") 로 사용해야 합니다.
            // 여기서 #root는 MethodSecurityExpressionRoot 인스턴스(MethodSecurityExpressionOperations 구현체)입니다.
            // DB에 저장된 SpEL 표현식은 MethodSecurityExpressionRoot의 메서드(hasPermission, hasRole 등)를
            // 호출하는 형태로 작성되어야 합니다.

        } else {
            log.debug("No dynamic method resource found for {}.{}.{} Using default static security if any.", className, methodName, httpMethod);
            // DB에 매핑된 동적 규칙이 없으면, `@PreAuthorize` 어노테이션에 직접 정의된 표현식이 평가됩니다.
            // 이 경우, `#dynamicAccessRule` 변수는 설정되지 않으므로, @PreAuthorize에서 이를 참조하면 NPE가 발생할 수 있습니다.
            // @PreAuthorize("(#dynamicAccessRule != null ? #dynamicAccessRule.getValue(#root) : true)")
            // 와 같이 기본 허용 로직을 추가하거나, 명시적으로 false 반환하도록 할 수 있습니다.
        }

        return ctx;
    }
}