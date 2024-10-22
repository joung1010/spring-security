package com.business.security.common.config.basic.authentication.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * <b> CustomAuthenticationProvider </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-10-22
 */
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        // 인증 절차
        //아이디 검증

        //비밀번호 검증

        return new UsernamePasswordAuthenticationToken(
                loginId
                , password
                , List.of(new SimpleGrantedAuthority("ROLE_USER"))
        ) // 권한정보 설정
                ;
    }

    @Override
    // 이 Provider가 처리할 인증에 대한 검증을 처리하는 메서드
    public boolean supports(Class<?> authentication) {
        //isAssignableFrom: 해당클레스를 상속하고 있는 자식클레스인지 확인
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
