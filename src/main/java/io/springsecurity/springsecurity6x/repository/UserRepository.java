package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.entity.Users;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List; // <<< 추가됨
import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    /**
     * username 으로 Users 엔티티를 조회하면서,
     * 연결된 Group, GroupRole, Role, RolePermission, Permission 엔티티를 모두 FETCH JOIN합니다.
     * 이를 통해 N+1 쿼리 문제를 방지하고 CustomUserDetails에서 모든 권한 정보를 효율적으로 로드합니다.
     */
    @Cacheable(value = "usersWithAuthorities", key = "#username")
    @Query("SELECT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +      // <<< LEFT JOIN FETCH로 변경 (사용자가 그룹에 속하지 않은 경우도 고려)
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "WHERE u.username = :username")
    Optional<Users> findByUsernameWithGroupsRolesAndPermissions(String username);

    @Cacheable(value = "usersWithAuthorities", key = "#id")
    @Query("SELECT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +      // <<< LEFT JOIN FETCH로 변경
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "WHERE u.id = :id")
    Optional<Users> findByIdWithGroupsRolesAndPermissions(Long id);

    // findByUsername은 남겨두되, 권한 로드 시에는 위 쿼리 사용
    Optional<Users> findByUsername(String username);

    // UserManagementService 에서 사용할 N+1 해결 쿼리
    @Query("SELECT DISTINCT u FROM Users u " +
            "LEFT JOIN FETCH u.userGroups ug " +
            "LEFT JOIN FETCH ug.group g " +
            "LEFT JOIN FETCH g.groupRoles gr " +
            "LEFT JOIN FETCH gr.role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p")
    List<Users> findAllWithDetails();
}

