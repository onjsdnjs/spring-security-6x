package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository; // @Repository 어노테이션 추가

import java.util.List;
import java.util.Optional;

@Repository // Spring Bean 으로 등록되도록 어노테이션 추가
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(String name);

    @Override
    void delete(Role role);

    @Query("select r from Role r where r.isExpression = 'N'")
    List<Role> findAllRolesWithoutExpression();

    /**
     * ID로 Role 엔티티를 조회하면서 연관된 Permissions를 즉시 가져옵니다.
     * `LEFT JOIN FETCH`를 사용하여 Role이 Permissions를 가지고 있지 않아도 Role 자체는 가져옵니다.
     * @param id 조회할 Role ID
     * @return 해당 Role 엔티티 (Optional)
     */
    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.permissions p WHERE r.id = :id")
    Optional<Role> findByIdWithPermissions(Long id); // 이 메서드를 추가합니다.
}