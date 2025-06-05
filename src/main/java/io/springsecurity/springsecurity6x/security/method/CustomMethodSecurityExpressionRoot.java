package io.springsecurity.springsecurity6x.security.method;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.entity.Role;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Spring Security의 SpEL 평가를 위한 루트 객체를 확장합니다.
 * DB에서 로드된 동적 MethodResource 정보와 권한 데이터를 SpEL 표현식에서 활용할 수 있도록 노출합니다.
 *
 */
public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot {

    private final Expression dynamicAccessExpression; // DB에서 로드된 SpEL 표현식 객체
    private MethodResource dbMethodResource; // DB에서 로드된 MethodResource 엔티티

    public CustomMethodSecurityExpressionRoot(Authentication authentication, MethodInvocation mi, Expression dynamicAccessExpression) {
        super(authentication);
        this.dynamicAccessExpression = dynamicAccessExpression;

        // 메서드 인자들을 SpEL 컨텍스트에 등록 (기본적으로 #a0, #p0 등으로 접근 가능)
        // 만약 인자 이름을 명시적으로 등록하고 싶다면, ParameterNameDiscoverer를 사용해야 합니다.
        // 예: root.setVariable("documentId", args[0]);
        // 여기서는 MethodSecurityExpressionRoot가 기본적으로 제공하는 기능을 활용합니다.
    }

    // MethodSecurityExpressionHandler에서 DB에서 로드된 MethodResource를 설정할 수 있도록 setter 추가
    public void setDbMethodResource(MethodResource dbMethodResource) {
        this.dbMethodResource = dbMethodResource;
    }

    /**
     * DB에서 로드된 SpEL 표현식을 평가하여 반환합니다.
     * @return SpEL 표현식 평가 결과
     */
    public boolean evaluateDbExpression() {
        if (dynamicAccessExpression == null) {
            return false; // DB에 표현식이 없으면 기본적으로 접근 거부 (정책에 따라 허용도 가능)
        }
        // `dynamicAccessExpression`을 현재 컨텍스트(즉, `this` 객체)에서 평가합니다.
        // `this`는 `MethodSecurityExpressionRoot`이므로 `authentication`, `permissionEvaluator` 등을 가집니다.
        // 따라서 `hasPermission()`, `hasRole()` 등의 SpEL 함수를 `dynamicAccessExpression` 내부에서 호출할 수 있습니다.
        return dynamicAccessExpression.getValue(this, Boolean.class);
    }

    /**
     * SpEL 표현식에서 `#root.dbRoles`로 접근하여
     * DB에서 이 메서드 리소스에 직접 할당된 역할 목록을 가져옵니다.
     * (이 역할들은 CustomUserDetails가 가진 역할과는 다를 수 있습니다.)
     */
    public Set<String> getDbRoles() {
        return Optional.ofNullable(dbMethodResource)
                .map(MethodResource::getMethodResourceRoles)
                .orElse(Collections.emptySet())
                .stream()
                .map(mrr -> mrr.getRole())
                .filter(java.util.Objects::nonNull)
                .map(Role::getRoleName)
                .collect(Collectors.toSet());
    }

    /**
     * SpEL 표현식에서 `#root.dbPermissions`로 접근하여
     * DB에서 이 메서드 리소스에 직접 할당된 권한 목록을 가져옵니다.
     * (이 권한들은 CustomUserDetails가 가진 권한과는 다를 수 있습니다.)
     */
    public Set<String> getDbPermissions() {
        return Optional.ofNullable(dbMethodResource)
                .map(MethodResource::getMethodResourcePermissions)
                .orElse(Collections.emptySet())
                .stream()
                .map(mrp -> mrp.getPermission())
                .filter(java.util.Objects::nonNull)
                .map(Permission::getName)
                .collect(Collectors.toSet());
    }

    // 추가적인 SpEL 함수를 여기에 정의할 수 있습니다.
    // 예: 특정 IP 주소 검사, 특정 시간대 검사 등.
}