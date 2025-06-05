package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.RoleHierarchyRelationship;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleHierarchyRelationshipRepository extends JpaRepository<RoleHierarchyRelationship, Long> {

    /**
     * 모든 역할 계층 관계를 조회하면서 상위/하위 Role 엔티티를 함께 가져옵니다.
     */
    @Query("SELECT rhr FROM RoleHierarchyRelationship rhr JOIN FETCH rhr.higherRole hr JOIN FETCH rhr.lowerRole lr ORDER BY hr.roleName ASC, lr.roleName ASC")
    List<RoleHierarchyRelationship> findAllWithRoles();

    /**
     * 특정 상위 역할과 하위 역할 간의 관계를 조회합니다.
     */
    Optional<RoleHierarchyRelationship> findByHigherRoleIdAndLowerRoleId(Long higherRoleId, Long lowerRoleId);
}
