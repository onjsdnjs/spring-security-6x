package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface GroupRepository extends JpaRepository<Group, Long> {
    Optional<Group> findByName(String name);

    /**
     * ID로 Group 엔티티를 조회하면서, 연결된 GroupRole과 Role을 FETCH JOIN합니다.
     * @param id 조회할 Group ID
     * @return 해당 Group 엔티티 (Optional)
     */
    @Query("SELECT g FROM Group g LEFT JOIN FETCH g.groupRoles gr LEFT JOIN FETCH gr.role WHERE g.id = :id")
    Optional<Group> findByIdWithRoles(Long id);

    /**
     * 모든 Group 엔티티를 조회하면서, 연결된 GroupRole과 Role을 FETCH JOIN합니다.
     * @return 모든 Group 엔티티 리스트
     */
    @Query("SELECT DISTINCT g FROM Group g LEFT JOIN FETCH g.groupRoles gr LEFT JOIN FETCH gr.role ORDER BY g.name ASC")
    List<Group> findAllWithRoles();
}
