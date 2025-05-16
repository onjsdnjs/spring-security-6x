package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.feature.auth.mfa.MfaAuthenticationFeature; // MfaAuthenticationFeature import
import jakarta.servlet.Filter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.util.*;
import java.util.stream.Collectors;

public class FeatureRegistry {
    private static final Logger log = LoggerFactory.getLogger(FeatureRegistry.class);

    private final Map<String, AuthenticationFeature> authFeatures = new HashMap<>();
    private final Map<String, StateFeature> stateFeatures = new HashMap<>();
    private final Map<String, Filter> factorFilters = new HashMap<>();
    private final ApplicationContext applicationContext;

    public FeatureRegistry(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        ServiceLoader.load(AuthenticationFeature.class, getClass().getClassLoader())
                .forEach(f -> {
                    AuthenticationFeature featureInstance = f;
                    if (f instanceof MfaAuthenticationFeature) { // 타입 체크로 변경
                        try {
                            featureInstance = f.getClass()
                                    .asSubclass(AuthenticationFeature.class)
                                    .getConstructor(ApplicationContext.class)
                                    .newInstance(this.applicationContext);
                            log.debug("Instantiated MfaAuthenticationFeature with ApplicationContext: {}", featureInstance.getClass().getName());
                        } catch (NoSuchMethodException nsme) {
                            log.warn("MfaAuthenticationFeature (id: 'mfa') does not have a constructor accepting ApplicationContext. Using default instance.", nsme);
                        } catch (Exception e) {
                            log.error("Error instantiating MfaAuthenticationFeature (id: 'mfa') with ApplicationContext. Using default instance.", e);
                        }
                    }
                    authFeatures.put(f.getId().toLowerCase(), featureInstance);
                    log.debug("Loaded AuthenticationFeature: ID='{}', Class='{}'", featureInstance.getId().toLowerCase(), featureInstance.getClass().getName());
                });

        ServiceLoader.load(StateFeature.class, getClass().getClassLoader())
                .forEach(f -> {
                    stateFeatures.put(f.getId().toLowerCase(), f);
                    log.debug("Loaded StateFeature: ID='{}', Class='{}'", f.getId().toLowerCase(), f.getClass().getName());
                });
    }

    public List<AuthenticationFeature> getAuthFeaturesFor(List<AuthenticationFlowConfig> flows) {
        if (flows == null || flows.isEmpty()) {
            return Collections.emptyList();
        }

        Set<AuthenticationFeature> featuresToApply = new LinkedHashSet<>();

        for (AuthenticationFlowConfig flow : flows) {
            String flowTypeNameLower = flow.getTypeName().toLowerCase();

            if ("mfa".equals(flowTypeNameLower)) {
                AuthenticationFeature mfaBaseFeature = authFeatures.get("mfa");
                if (mfaBaseFeature != null) {
                    featuresToApply.add(mfaBaseFeature);
                    log.debug("Added MfaAuthenticationFeature for MFA flow '{}'", flow.getTypeName());
                } else {
                    log.warn("MfaAuthenticationFeature (id: 'mfa') not found. MFA flow '{}' might not be fully configured.", flow.getTypeName());
                }

                if (flow.getStepConfigs() != null) {
                    for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                        String stepTypeNameLower = step.getType().toLowerCase();
                        AuthenticationFeature stepFeature = authFeatures.get(stepTypeNameLower);
                        if (stepFeature != null) {
                            // MfaAuthenticationFeature 자체를 스텝 Feature로 다시 추가하지 않도록 방지
                            if (!stepFeature.getId().equalsIgnoreCase("mfa")) {
                                featuresToApply.add(stepFeature);
                                log.debug("Added step-specific AuthenticationFeature '{}' for step type '{}' in MFA flow '{}'",
                                        stepFeature.getClass().getSimpleName(), stepTypeNameLower, flow.getTypeName());
                            }
                        } else {
                            log.warn("No AuthenticationFeature found for step type '{}' in MFA flow '{}'", stepTypeNameLower, flow.getTypeName());
                        }
                    }
                }
            } else { // 단일 인증 플로우
                AuthenticationFeature singleAuthFeature = authFeatures.get(flowTypeNameLower);
                if (singleAuthFeature != null) {
                    featuresToApply.add(singleAuthFeature);
                    log.debug("Added AuthenticationFeature '{}' for single auth flow '{}'",
                            singleAuthFeature.getClass().getSimpleName(), flowTypeNameLower);
                } else {
                    log.warn("No AuthenticationFeature found for single auth flow type: {}", flowTypeNameLower);
                }
            }
        }

        List<AuthenticationFeature> sortedFeatures = new ArrayList<>(featuresToApply);
        sortedFeatures.sort(Comparator.comparingInt(AuthenticationFeature::getOrder));

        log.info("Final sorted list of AuthenticationFeatures to be applied: {}",
                sortedFeatures.stream().map(f -> f.getId() + "(" + f.getClass().getSimpleName() + ")").collect(Collectors.toList()));
        return sortedFeatures;
    }

    public List<StateFeature> getStateFeaturesFor(List<AuthenticationFlowConfig> flows) {
        if (flows == null || flows.isEmpty()) {
            return Collections.emptyList();
        }
        Set<String> stateIds = new HashSet<>();
        for (AuthenticationFlowConfig f : flows) {
            if (f.getStateConfig() != null && f.getStateConfig().state() != null) {
                stateIds.add(f.getStateConfig().state().toLowerCase());
            }
        }

        List<StateFeature> list = new ArrayList<>();
        for (String id : stateIds) {
            StateFeature sf = stateFeatures.get(id);
            if (sf != null) {
                list.add(sf);
            } else {
                log.warn("StateFeature not found in registry for state ID: {}", id);
            }
        }
        log.info("Selected StateFeatures to apply: {}",
                list.stream().map(f -> f.getId() + "(" + f.getClass().getSimpleName() + ")").collect(Collectors.toList()));
        return list;
    }

    public void registerFactorFilter(String factorType, Filter filter) {
        factorFilters.put(factorType.toLowerCase(), filter);
        log.debug("Registered factor filter: Type='{}', Filter='{}'", factorType.toLowerCase(), filter.getClass().getName());
    }

    public Filter getFactorFilter(String factorType) {
        Filter filter = factorFilters.get(factorType.toLowerCase());
        if (filter == null) {
            log.warn("No factor filter found for type: {}", factorType.toLowerCase());
        }
        return filter;
    }

    public AuthenticationFeature getAuthenticationFeature(String featureId) {
        return authFeatures.get(featureId.toLowerCase());
    }
}
