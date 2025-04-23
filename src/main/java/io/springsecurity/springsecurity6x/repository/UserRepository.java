package io.springsecurity.springsecurity6x.repository;

import io.springsecurity.springsecurity6x.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByUsername(String username);

}

