package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.Resources; // Resources 엔티티 임포트
import io.springsecurity.springsecurity6x.entity.ResourcesRole; // ResourcesRole 조인 엔티티 임포트
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository; // @Repository 어노테이션 추가

import java.util.List;
import java.util.Optional;

@Repository // Spring Bean으로 등록되도록 어노테이션 추가
public interface ResourcesRepository extends JpaRepository<Resources, Long> {

    Optional<Resources> findByResourceNameAndHttpMethod(String resourceName, String httpMethod);

    /**
     * 모든 Resources를 orderNum 순으로 정렬하여 조회하면서,
     * 연결된 ResourcesRole과 Role을 FETCH JOIN 합니다.
     * @return Resources 리스트
     */
    @Query("SELECT DISTINCT r FROM Resources r " +
            "LEFT JOIN FETCH r.resourcesRoles rr " + // ResourcesRole 조인
            "LEFT JOIN FETCH rr.role " +           // Role 조인
            "WHERE r.resourceType = 'url' ORDER BY r.orderNum DESC")
    List<Resources> findAllResources();

    /**
     * ID로 Resources 엔티티를 조회하면서,
     * 연결된 ResourcesRole과 Role을 FETCH JOIN합니다.
     * @param id 조회할 Resources ID
     * @return 해당 Resources 엔티티 (Optional)
     */
    @Query("SELECT r FROM Resources r " +
            "LEFT JOIN FETCH r.resourcesRoles rr " + // ResourcesRole 조인
            "LEFT JOIN FETCH rr.role " +           // Role 조인
            "WHERE r.id = :id")
    Optional<Resources> findByIdWithRoles(Long id); // 이 메서드를 추가합니다.
}
