package io.springsecurity.springsecurity6x.security.token.parser;

import java.time.Instant;
import java.util.List;

public record ParsedJwt(String id, String subject, Instant expiration, List<String> roles) {}