package io.springsecurity.springsecurity6x.security.permission;

import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.repository.PermissionRepository;
import io.springsecurity.springsecurity6x.security.filter.MfaGrantedAuthority;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

@Component("customPermissionEvaluator") // 빈 이름 지정
@RequiredArgsConstructor
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final PermissionRepository permissionRepository; // Permission 엔티티를 다룰 Repository
    // 다른 서비스 주입 가능 (예: 특정 도메인 객체의 소유자를 찾는 서비스)

    /**
     * hasPermission(targetDomainObject, permission)
     * 예: @PreAuthorize("hasPermission(#document, 'READ')")
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            return false;
        }

        // targetDomainObject가 null인 경우 (클래스 레벨 권한 등)
        if (targetDomainObject == null) {
            return checkPermissionForAuthorities(authentication.getAuthorities(), (String) permission);
        }

        // 객체 레벨 권한 (예: Document 객체에 대한 READ 권한)
        // 여기에 도메인 객체의 특정 속성(예: 소유자)을 확인하는 로직을 추가할 수 있습니다.
        String targetType = targetDomainObject.getClass().getSimpleName().toUpperCase(); // 클래스명으로 targetType
        String requiredAction = (String) permission; // 예: "READ", "WRITE"

        // 사용자가 해당 도메인 객체 타입에 대해 특정 액션을 수행할 권한이 있는지 확인
        // 먼저, Authentication의 GrantedAuthority에 해당 Permission 문자열이 있는지 확인
        if (checkPermissionForAuthorities(authentication.getAuthorities(), targetType + "_" + requiredAction)) {
            // 추가적인 로직: 도메인 객체 자체가 가진 속성(예: 소유자) 확인
            if (targetType.equals("DOCUMENT")) { // 예시: Document 객체
                // Document document = (Document) targetDomainObject;
                // if (authentication.getName().equals(document.getOwnerUsername())) {
                //     return true; // 소유자는 항상 허용
                // }
            }
            // TODO: 여기에 동적 인가 로직 확장 (AI의 판단을 포함)
            // 현재는 GrantedAuthority에 Permission이 있는지만 확인
            return true;
        }
        return false;
    }

    /**
     * hasPermission(targetId, targetType, permission)
     * 예: @PreAuthorize("hasPermission(#documentId, 'Document', 'READ')")
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || !(permission instanceof String)) {
            return false;
        }

        String requiredAction = (String) permission;
        String fullPermissionName = targetType.toUpperCase() + "_" + requiredAction.toUpperCase(); // 예: "DOCUMENT_READ"

        // 1. Authentication의 GrantedAuthority에 해당 Permission 문자열이 있는지 확인
        if (checkPermissionForAuthorities(authentication.getAuthorities(), fullPermissionName)) {
            return true;
        }

        // 2. 추가적인 로직: DB에서 해당 targetId와 targetType에 대한 권한 관계를 조회
        // 예: targetId가 특정 문서의 ID이고, targetType이 "Document"일 때,
        //     해당 문서에 대한 특정 권한이 사용자에게 직접 부여되었는지 확인하는 복잡한 로직
        //     (이 부분은 DB 설계 및 비즈니스 로직에 따라 매우 달라질 수 있음)
        /*
        if (targetType.equalsIgnoreCase("DOCUMENT")) {
            Document document = documentRepository.findById(targetId).orElse(null);
            if (document != null && authentication.getName().equals(document.getOwnerUsername())) {
                return true; // 문서 소유자는 항상 모든 권한 가짐
            }
        }
        */

        log.debug("User {} does not have permission '{}' on target {} (ID: {}).",
                authentication.getName(), fullPermissionName, targetType, targetId);
        return false;
    }

    /**
     * Authentication 객체의 GrantedAuthority 목록에서 특정 권한 문자열을 가지고 있는지 확인합니다.
     */
    private boolean checkPermissionForAuthorities(Collection<? extends GrantedAuthority> authorities, String permissionName) {
        return authorities.stream()
                .anyMatch(authority -> authority.getAuthority().equalsIgnoreCase(permissionName));
    }

    /**
     * Authentication 객체의 GrantedAuthority 목록에 권한을 추가합니다.
     * (이 메서드는 권한을 '검증'하는 PermissionEvaluator의 역할은 아님.
     * 하지만 GrantedAuthority 구성을 명확히 하기 위해 예시로 포함)
     */
    private void addPermissionsToAuthorities(Set<GrantedAuthority> authorities, Set<Permission> permissions) {
        permissions.forEach(p -> {
            // "DOCUMENT_READ" 와 같은 형태로 Authority를 생성
            authorities.add(new MfaGrantedAuthority(p.getName()));
        });
    }
}
