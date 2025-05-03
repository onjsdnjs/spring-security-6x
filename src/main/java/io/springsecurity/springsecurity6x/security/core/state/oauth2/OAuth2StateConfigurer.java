package io.springsecurity.springsecurity6x.security.core.state.oauth2;

import io.springsecurity.springsecurity6x.security.core.state.AuthenticationStateConfigurer;

public interface OAuth2StateConfigurer extends AuthenticationStateConfigurer {

    OAuth2StateConfigurer tokenUri(String tokenUri);

    OAuth2StateConfigurer clientId(String clientId);

    OAuth2StateConfigurer clientSecret(String clientSecret);

    OAuth2StateConfigurer scope(String scope);

}
