package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GroupRepository extends JpaRepository<Group, Long> {
    /**
     * 그룹 이름(name)으로 Group 엔티티를 조회합니다.
     * @param name 조회할 그룹 이름
     * @return 해당 Group 엔티티 (Optional)
     */
    Optional<Group> findByName(String name);
}
