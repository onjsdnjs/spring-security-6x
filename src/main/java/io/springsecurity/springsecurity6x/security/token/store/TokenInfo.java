package io.springsecurity.springsecurity6x.security.token.store;

import java.time.Instant;

public record TokenInfo(String username, Instant expiry) {}
