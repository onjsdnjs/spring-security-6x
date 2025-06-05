package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.entity.Users;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    /**
     * username 으로 Users 엔티티를 조회하면서,
     * 연결된 Group, GroupRole, Role, RolePermission, Permission 엔티티를 모두 FETCH JOIN합니다.
     * 이를 통해 N+1 쿼리 문제를 방지하고 CustomUserDetails에서 모든 권한 정보를 효율적으로 로드합니다.
     */
    @Cacheable(value = "usersWithAuthorities", key = "#username") // 캐시 이름 변경
    @Query("SELECT u FROM Users u " +
            "JOIN FETCH u.userGroups ug " + // UserGroup 조인
            "JOIN FETCH ug.group g " +      // Group 조인
            "JOIN FETCH g.groupRoles gr " + // GroupRole 조인
            "JOIN FETCH gr.role r " +       // Role 조인
            "LEFT JOIN FETCH r.rolePermissions rp " + // RolePermission 조인 (Optional 관계일 수 있으므로 LEFT)
            "LEFT JOIN FETCH rp.permission p " + // Permission 조인 (Optional 관계일 수 있으므로 LEFT)
            "WHERE u.username = :username")
    Optional<Users> findByUsernameWithGroupsRolesAndPermissions(String username); // 새로운 쿼리

    @Cacheable(value = "usersWithAuthorities", key = "#id") // 캐시 이름 변경
    @Query("SELECT u FROM Users u " +
            "JOIN FETCH u.userGroups ug " + // UserGroup 조인
            "JOIN FETCH ug.group g " +      // Group 조인
            "JOIN FETCH g.groupRoles gr " + // GroupRole 조인
            "JOIN FETCH gr.role r " +       // Role 조인
            "LEFT JOIN FETCH r.rolePermissions rp " + // RolePermission 조인 (Optional 관계일 수 있으므로 LEFT)
            "LEFT JOIN FETCH rp.permission p " + // Permission 조인 (Optional 관계일 수 있으므로 LEFT)
            "WHERE u.id = :id")
    Optional<Users> findByIdWithGroupsRolesAndPermissions(Long id); // 새로운 쿼리

    // 기존 findByUsername은 남겨두되, 권한 로드 시에는 위 쿼리 사용
    Optional<Users> findByUsername(String username);

}

