package com.business.security.common.config.basic.authentication.userDetailService;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

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
        return User
                .withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();
    }
}
