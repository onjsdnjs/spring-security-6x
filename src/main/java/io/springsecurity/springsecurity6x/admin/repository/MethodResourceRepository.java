package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface MethodResourceRepository extends JpaRepository<MethodResource, Long> {

    /**
     * 클래스명, 메서드명, HTTP 메서드를 기준으로 MethodResource를 조회합니다.
     * 연관된 MethodResourceRole, Role, MethodResourcePermission, Permission을 함께 가져옵니다.
     * @param className 메서드가 속한 클래스 전체 이름
     * @param methodName 메서드 이름
     * @param httpMethod HTTP 메서드 (예: "GET", "POST", "ALL")
     * @return 해당 MethodResource (Optional)
     */
    @Query("SELECT mr FROM MethodResource mr " +
            "LEFT JOIN FETCH mr.methodResourceRoles mrr " +
            "LEFT JOIN FETCH mrr.role r " +
            "LEFT JOIN FETCH mr.methodResourcePermissions mrp " +
            "LEFT JOIN FETCH mrp.permission p " +
            "WHERE mr.className = :className AND mr.methodName = :methodName AND mr.httpMethod = :httpMethod")
    Optional<MethodResource> findByClassNameAndMethodNameAndHttpMethod(String className, String methodName, String httpMethod);

    /**
     * 모든 MethodResource를 orderNum 순으로 정렬하여 조회하면서,
     * 연관된 MethodResourceRole, Role, MethodResourcePermission, Permission을 함께 가져옵니다.
     * @return MethodResource 리스트
     */
    @Query("SELECT DISTINCT mr FROM MethodResource mr " + // DISTINCT를 사용하여 중복 제거
            "LEFT JOIN FETCH mr.methodResourceRoles mrr " +
            "LEFT JOIN FETCH mrr.role r " +
            "LEFT JOIN FETCH mr.methodResourcePermissions mrp " +
            "LEFT JOIN FETCH mrp.permission p " +
            "ORDER BY mr.orderNum ASC")
    List<MethodResource> findAllByOrderByOrderNumAsc();

    /**
     * ID로 MethodResource 엔티티를 조회하면서,
     * 연관된 MethodResourceRole, Role, MethodResourcePermission, Permission을 함께 가져옵니다.
     * @param id 조회할 MethodResource ID
     * @return 해당 MethodResource (Optional)
     */
    @Query("SELECT mr FROM MethodResource mr " +
            "LEFT JOIN FETCH mr.methodResourceRoles mrr " +
            "LEFT JOIN FETCH mrr.role r " +
            "LEFT JOIN FETCH mr.methodResourcePermissions mrp " +
            "LEFT JOIN FETCH mrp.permission p " +
            "WHERE mr.id = :id")
    Optional<MethodResource> findByIdWithRolesAndPermissions(Long id); // 이 메서드를 추가합니다.

    // 특정 클래스의 모든 메서드 리소스 조회 (관리자 UI 등에서 활용 가능)
    // 이 쿼리도 조인 fetch를 추가하는 것이 좋습니다.
    @Query("SELECT mr FROM MethodResource mr " +
            "LEFT JOIN FETCH mr.methodResourceRoles mrr " +
            "LEFT JOIN FETCH mrr.role r " +
            "LEFT JOIN FETCH mr.methodResourcePermissions mrp " +
            "LEFT JOIN FETCH mrp.permission p " +
            "WHERE mr.className = :className ORDER BY mr.orderNum ASC")
    List<MethodResource> findByClassNameOrderByOrderNumAsc(String className);
}
