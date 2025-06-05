package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    @Query("SELECT u FROM Users u JOIN FETCH u.userRoles r JOIN FETCH r.permissions p WHERE u.username = :username")
    Optional<Users> findByUsernameWithRolesAndPermissions(String username);

    // 기존 findByUsername은 남겨두되, 권한 로드 시에는 위 쿼리 사용
    Optional<Users> findByUsername(String username);

}

