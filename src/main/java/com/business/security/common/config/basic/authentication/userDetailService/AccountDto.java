package com.business.security.common.config.basic.authentication.userDetailService;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * <b> AccountDto </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-10-29
 */

@Getter
@Builder
public class AccountDto {
    private String username;
    private String password;
    private Collection<GrantedAuthority> authorities;

    @Builder.Default
    private boolean isAccountNonExpired = true;
}
