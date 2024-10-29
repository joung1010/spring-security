package com.business.security.common.config.basic.authentication.userDetailService;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * <b> CustomAuthenticationProviderForUserDetail </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-10-29
 */

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProviderForUserDetail implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        //아이디 검증
        UserDetails userDetails = Optional.ofNullable(userDetailsService.loadUserByUsername(loginId))
                .orElseThrow(() -> new UsernameNotFoundException("회원 미존재"));

        //비밀번호 검증

        return new UsernamePasswordAuthenticationToken(
                userDetails.getUsername()
                , userDetails.getPassword()
                , userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
