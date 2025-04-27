package io.springsecurity.springsecurity6x.security.token.creator;

import lombok.Data;
import java.util.List;
import java.util.Map;

@Data
public class TokenRequest {
    private String tokenType;
    private String username;
    private long validity;
    private List<String> roles;
    private Map<String,Object> claims;
}
