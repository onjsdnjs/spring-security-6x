package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.jwt.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users, Long> {
}
