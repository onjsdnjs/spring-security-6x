package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository; // @Repository 어노테이션 추가

import java.util.Optional;

@Repository // Spring Data JPA Repository로 등록
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    /**
     * 권한 이름(name)으로 Permission 엔티티를 조회합니다.
     * @param name 조회할 권한 이름 (예: "DOCUMENT_READ")
     * @return 해당 Permission 엔티티 (Optional)
     */
    Optional<Permission> findByName(String name);

    // 필요시 targetType과 actionType으로 조회하는 메서드 추가 가능
    // List<Permission> findByTargetTypeAndActionType(String targetType, String actionType);
}
