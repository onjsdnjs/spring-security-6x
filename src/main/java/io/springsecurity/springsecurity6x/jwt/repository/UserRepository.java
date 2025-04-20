package io.springsecurity.springsecurity6x.jwt.repository;

import io.springsecurity.springsecurity6x.jwt.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public class UserRepository implements JpaRepository<Users, Long> {
}
