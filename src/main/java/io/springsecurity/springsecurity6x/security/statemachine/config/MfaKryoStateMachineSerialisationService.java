package io.springsecurity.springsecurity6x.security.statemachine.config;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.serializers.DefaultSerializers;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.service.CustomUserDetails;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.statemachine.kryo.KryoStateMachineSerialisationService;
import org.springframework.statemachine.kryo.StateMachineContextSerializer;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.statemachine.support.ObservableMap;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class MfaKryoStateMachineSerialisationService extends KryoStateMachineSerialisationService<MfaState, MfaEvent> {

    @Override
    protected void configureKryoInstance(Kryo kryo) {

        super.configureKryoInstance(kryo);
        kryo.setRegistrationRequired(false);
        kryo.register(DefaultStateMachineContext.class);
        kryo.register(DefaultExtendedState.class);
        kryo.register(FactorContext.class);
        if (MfaState.class.isEnum()) {
            kryo.register(MfaState.class, new DefaultSerializers.EnumSerializer(MfaState.class));
        }
        if (MfaEvent.class.isEnum()) {
            kryo.register(MfaEvent.class, new DefaultSerializers.EnumSerializer(MfaEvent.class));
        }

        kryo.register(HashMap.class);
        kryo.register(ArrayList.class);
        kryo.register(LinkedHashMap.class); 
        kryo.register(ObservableMap.class); 
        kryo.register(ConcurrentHashMap.class); 
        kryo.register(CopyOnWriteArrayList.class); 
        kryo.register(AtomicReference.class, new AtomicReferenceSerializer());
        kryo.register(AtomicInteger.class, new AtomicIntegerSerializer()); 
        kryo.register(Authentication.class); 
        kryo.register(AuthType.class); 
        kryo.register(Instant.class); 
        kryo.register(UsernamePasswordAuthenticationToken.class); 
        try {
            Class<?> unmodifiableListClass = Collections.unmodifiableList(new java.util.ArrayList<>()).getClass();
            kryo.register(unmodifiableListClass);
            Class<?> emptyListClass = Collections.emptyList().getClass();
            if (kryo.getRegistration(emptyListClass) == null) {
                kryo.register(emptyListClass);
            }
        } catch (Exception e) {
            log.error("Failed to register unmodifiable collection types for Kryo", e);
        }
        kryo.register(SimpleGrantedAuthority.class);
        kryo.register(CustomUserDetails.class);
        kryo.register(Users.class);
        kryo.addDefaultSerializer(DefaultStateMachineContext.class, new StateMachineContextSerializer<MfaState, MfaEvent>());
    }
}
