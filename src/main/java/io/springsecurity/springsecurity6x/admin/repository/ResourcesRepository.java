package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.Resources;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface ResourcesRepository extends JpaRepository<Resources, Long> {

    // 기존 findByResourceNameAndHttpMethod
    Optional<Resources> findByResourceNameAndHttpMethod(String resourceName, String httpMethod);

    /**
     * 모든 Resources를 orderNum 순으로 정렬하여 조회하면서, 연결된 ResourcesRole과 Role을 FETCH JOIN합니다.
     * @return Resources 리스트
     */
    @Query("SELECT DISTINCT r FROM Resources r LEFT JOIN FETCH r.resourcesRoles rr LEFT JOIN FETCH rr.role WHERE r.resourceType = 'url' ORDER BY r.orderNum DESC")
    List<Resources> findAllResources(); // 이름을 findAllResources로 그대로 유지하고 쿼리만 변경

    /**
     * ID로 Resources 엔티티를 조회하면서, 연결된 ResourcesRole과 Role을 FETCH JOIN합니다.
     * @param id 조회할 Resources ID
     * @return 해당 Resources 엔티티 (Optional)
     */
    @Query("SELECT r FROM Resources r LEFT JOIN FETCH r.resourcesRoles rr LEFT JOIN FETCH rr.role WHERE r.id = :id")
    Optional<Resources> findByIdWithRoles(Long id); // 추가
}
