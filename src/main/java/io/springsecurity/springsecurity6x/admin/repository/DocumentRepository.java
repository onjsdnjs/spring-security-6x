package io.springsecurity.springsecurity6x.admin.repository;

import io.springsecurity.springsecurity6x.entity.Document;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentRepository extends JpaRepository<Document, Long> { }