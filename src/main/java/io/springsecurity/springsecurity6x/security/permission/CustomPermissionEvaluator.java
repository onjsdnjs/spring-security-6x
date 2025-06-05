package io.springsecurity.springsecurity6x.security.permission;

import io.springsecurity.springsecurity6x.admin.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.security.core.auth.PermissionAuthority;
import io.springsecurity.springsecurity6x.security.core.auth.RoleAuthority;
import io.springsecurity.springsecurity6x.security.service.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;

@Component("customPermissionEvaluator")
@RequiredArgsConstructor
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final PermissionRepository permissionRepository;
    // 필요한 경우 다른 서비스 (예: 객체 소유자 확인 서비스) 주입

    /**
     * hasPermission(targetDomainObject, permission)
     * 예: @PreAuthorize("hasPermission(#document, 'READ')")
     * Authentication이 가진 RoleAuthority와 PermissionAuthority를 활용하여 권한을 평가합니다.
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied: Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredPermissionName = ((String) permission).toUpperCase(); // 요구되는 권한명 (예: "READ", "WRITE")

        // 1. 사용자에게 직접 부여된 PermissionAuthority 확인
        boolean hasDirectPermissionAuthority = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getPermissionName().equalsIgnoreCase(requiredPermissionName));

        if (hasDirectPermissionAuthority) {
            log.debug("User {} has direct PermissionAuthority '{}'. Access granted.", authentication.getName(), requiredPermissionName);
            // TODO: 이 단계에서 targetDomainObject에 대한 추가적인 복잡한 로직을 수행할 수 있습니다.
            // (예: hasPermission(#document, 'OWNER_CHECK')와 같은 특정 권한에 대한 객체 속성 검사)
            return true;
        }

        // 2. 사용자가 가진 RoleAuthority를 통해 해당 Role이 Permission을 포함하는지 확인
        // (CustomUserDetails에서 이미 로드된 계층적 정보를 활용)
        boolean hasRoleGrantingPermission = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof RoleAuthority)
                .map(auth -> (RoleAuthority) auth)
                .anyMatch(ra -> {
                    if (authentication.getPrincipal() instanceof CustomUserDetails) {
                        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
                        // UserDetails에서 GroupRole, RolePermission 관계를 통해 Permission을 직접 찾습니다.
                        // 이 부분은 CustomUserDetails에서 권한이 이미 HashSet에 추가되었으므로,
                        // 여기서 다시 N+1 쿼리를 유발하지 않고 userDetails.getAuthorities()를 한 번 더 필터링하는 것이 더 효율적입니다.
                        // 즉, 이미 모든 PermissionAuthority가 authorities에 있으므로,
                        // 위 `hasDirectPermissionAuthority`에서 이미 처리되었어야 합니다.
                        // 따라서 이 블록은 'Role hierarchy' (RoleAuthority 간의 계층)를 통해 암묵적으로 얻는 권한에 더 적합합니다.
                        // RoleAuthority의 getAuthorities()는 상속된 역할을 포함하지 않으므로, RoleHierarchy가 필요합니다.
                        // 하지만 CustomUserDetails는 모든 하위 권한을 GrantedAuthority로 이미 추가했으므로,
                        // 이 부분이 불필요할 수 있습니다.
                        // 현재 설계에서는 RoleHierarchy는 RoleAuthority의 getAuthority()에 ROLE_ 접두사를 붙인 문자열만 처리합니다.
                        // PermissionAuthority는 ROLE_ 접두사가 없으므로 RoleHierarchy의 영향을 받지 않습니다.
                        // 따라서, 이 `hasRoleGrantingPermission` 로직은 CustomUserDetails가 `ROLE_` 프리픽스 권한 외에
                        // `Permission` 자체를 포함하는 `GrantedAuthority`를 반환했다면, 위 `hasDirectPermissionAuthority` 로직으로 충분합니다.
                        // 이 부분은 실제 동작을 보면서 더 최적화할 수 있습니다.
                        return false; // 현재 설계에서는 위 `hasDirectPermissionAuthority`로 충분 (혹은 RoleHierarchy가 Permission을 상속하는 경우)
                    }
                    return false;
                });

        if (hasRoleGrantingPermission) {
            log.debug("User {} has a Role granting Permission '{}'. Access granted.", authentication.getName(), requiredPermissionName);
            return true;
        }

        log.debug("Permission evaluation denied for user {} for target {} and permission '{}'.",
                authentication.getName(), targetDomainObject != null ? targetDomainObject.getClass().getSimpleName() : "null", requiredPermissionName);
        return false;
    }

    /**
     * hasPermission(targetId, targetType, permission)
     * 예: @PreAuthorize("hasPermission(#documentId, 'Document', 'WRITE')")
     * 이 메서드는 특정 ID와 타입에 대한 권한을 평가할 때 사용됩니다.
     *
     * @param targetId SpEL 표현식에서 #documentId와 같이 전달되는 객체의 ID
     * @param targetType SpEL 표현식에서 'Document'와 같이 전달되는 대상 객체의 타입 문자열
     * @param permission SpEL 표현식에서 'WRITE'와 같이 전달되는 요구되는 행동 타입 문자열
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            log.debug("Permission evaluation denied (by ID): Authentication null/unauthenticated or permission not String.");
            return false;
        }

        String requiredAction = (String) permission;
        String fullPermissionName = targetType.toUpperCase() + "_" + requiredAction.toUpperCase(); // 예: "DOCUMENT_WRITE"

        // CustomUserDetails에서 이미 로드된 PermissionAuthority를 활용하여 권한 검사
        // User의 authorities에 'DOCUMENT_WRITE'라는 PermissionAuthority가 있는지 확인
        boolean granted = authentication.getAuthorities().stream()
                .filter(auth -> auth instanceof PermissionAuthority)
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getPermissionName().equalsIgnoreCase(fullPermissionName) &&
                        (pa.getTargetType() == null || pa.getTargetType().equalsIgnoreCase(targetType))); // 대상 타입도 일치하는지 확인

        if (granted) {
            log.debug("User {} has PermissionAuthority '{}' for target ID {} and type '{}'. Access granted.",
                    authentication.getName(), fullPermissionName, targetId, targetType);
            // TODO: 여기에 객체 소유권 확인 등 추가적인 DB 조회 기반의 동적 인가 로직을 구현합니다.
            //       이 부분이 가장 중요한 객체 레벨 보안의 핵심입니다.
            //       예: documentRepository.findById(targetId).map(doc -> doc.getOwnerId().equals(authentication.getPrincipal().getId())).orElse(false);
            return true;
        }

        // RoleAuthority를 통한 권한 확인 (역할 계층에 따라 Permission이 부여되는 경우)
        // CustomUserDetails는 이미 RoleAuthority와 PermissionAuthority를 분리했으므로,
        // RoleHierarchy의 `getGrantedAuthorities(Collection<? extends GrantedAuthority> authorities)` 메서드를 사용하여
        // 해당 Authentication에 부여된 모든 (상속된) 권한을 가져온 후, 그 안에 fullPermissionName이 있는지 확인하는 것이 더 정확합니다.
        Collection<? extends GrantedAuthority> allGrantedAuthorities = authentication.getAuthorities();
        if (getRoleHierarchy() != null) { // CustomMethodSecurityExpressionHandler에서 RoleHierarchy가 주입된 경우
            allGrantedAuthorities = getRoleHierarchy().getGrantedAuthorities(authentication.getAuthorities());
        }

        boolean hasRoleGrantingPermissionViaHierarchy = allGrantedAuthorities.stream()
                .filter(auth -> auth instanceof PermissionAuthority) // RoleHierarchy가 PermissionAuthority를 생성하지는 않지만,
                // 이미 PermissionAuthority가 authority에 추가되어 있으므로 재확인
                .map(auth -> (PermissionAuthority) auth)
                .anyMatch(pa -> pa.getPermissionName().equalsIgnoreCase(fullPermissionName) &&
                        (pa.getTargetType() == null || pa.getTargetType().equalsIgnoreCase(targetType)));

        if (hasRoleGrantingPermissionViaHierarchy) {
            log.debug("User {} has a Role granting Permission '{}' via RoleHierarchy for target ID {} and type '{}'. Access granted.",
                    authentication.getName(), fullPermissionName, targetId, targetType);
            return true;
        }


        log.debug("Permission evaluation denied for user {} on target ID {} (type '{}') with permission '{}'.",
                authentication.getName(), targetId, targetType, fullPermissionName);
        return false;
    }
}