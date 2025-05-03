package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * FeatureRegistrar 및 PlatformBootstrap이 사용할
 * SecurityFeature 빈 목록을 제공하는 컴포넌트입니다.
 */
@Getter
@Component
public class FeatureProvider {

    private final List<AuthenticationFeature> features;

    public FeatureProvider(List<AuthenticationFeature> features) {
        this.features = features;
    }

}
