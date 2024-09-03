package com.business.security.common.config.basic.authentication.process.httpBasic;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * <b> CustomAuthenticationEntryPoint </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-08-06
 */
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    public static final String BASIC_AUTHENTICATION_HEADER = "WWW-Authenticate";

    @Override
    public void commence(HttpServletRequest request
            , HttpServletResponse response
            , AuthenticationException authException) throws IOException, ServletException {

        response.setHeader(BASIC_AUTHENTICATION_HEADER, "Basic realm=security");
        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }
}
