package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.domain.UserDto;
import io.springsecurity.springsecurity6x.security.service.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component("restAuthenticationProvider")
@RequiredArgsConstructor
public class RestAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(loginId);

        if(!passwordEncoder.matches(password, userDetails.getPassword())){
            throw new BadCredentialsException("Invalid password");
        }
        UserDto userDto = modelMapper.map(userDetails.getAccount(), UserDto.class);
        return new RestAuthenticationToken(userDto, userDetails.getPassword(), userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(RestAuthenticationToken.class);
    }
}
