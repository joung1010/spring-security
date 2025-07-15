package com.business.security.common.config.basic.authentication.provider;

import com.business.security.common.config.basic.exception.CustomException;
import com.business.security.common.config.basic.exception.DefaultAuthenticationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * <b> EventCustomAuthenticationProvider </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-15
 */

@RequiredArgsConstructor
public class EventCustomAuthenticationProvider  implements AuthenticationProvider {

    private final AuthenticationEventPublisher authenticationEventPublisher;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if(authentication.getName().equals("admin")) {
            authenticationEventPublisher.publishAuthenticationFailure(new CustomException("CustomException"), authentication);

            throw new CustomException("CustomException");
        }else if(authentication.getName().equals("db")){
            authenticationEventPublisher.publishAuthenticationFailure(new DefaultAuthenticationException("DefaultAuthenticationException"), authentication);

            throw new DefaultAuthenticationException("DefaultAuthenticationException");
        }
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
