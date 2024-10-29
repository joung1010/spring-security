package com.business.security.common.config.basic.authentication.userDetailService;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

/**
 * <b> CustomUserDetailService </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-10-29
 */

public class CustomUserDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        AccountDto user = AccountDto.builder()
                .username(username)
                .password("{noop}1111")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                .isAccountNonExpired(true)
                .build();

        return new CustomUserDetails(user);

    }
}
