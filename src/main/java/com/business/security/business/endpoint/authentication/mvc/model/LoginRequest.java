package com.business.security.business.endpoint.authentication.mvc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * <b> LoginRequest </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-01-14
 */

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    public String username;
    public String password;
}
