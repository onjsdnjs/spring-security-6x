package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.entity.MethodResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface MethodResourceRepository extends JpaRepository<MethodResource, Long> {

    /**
     * 클래스명, 메서드명, HTTP 메서드를 기준으로 MethodResource를 조회합니다.
     * @param className 메서드가 속한 클래스 전체 이름
     * @param methodName 메서드 이름
     * @param httpMethod HTTP 메서드 (예: "GET", "POST", "ALL")
     * @return 해당 MethodResource (Optional)
     */
    Optional<MethodResource> findByClassNameAndMethodNameAndHttpMethod(String className, String methodName, String httpMethod);

    /**
     * 모든 MethodResource를 orderNum 순으로 정렬하여 조회합니다.
     * @return MethodResource 리스트
     */
    List<MethodResource> findAllByOrderByOrderNumAsc();

    // 특정 클래스의 모든 메서드 리소스 조회 (관리자 UI 등에서 활용 가능)
    List<MethodResource> findByClassNameOrderByOrderNumAsc(String className);
}
