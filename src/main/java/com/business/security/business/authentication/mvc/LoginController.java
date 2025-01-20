/*
package com.business.security.business.authentication.mvc;

import com.business.security.business.authentication.mvc.model.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

*/
/**
 * <b> LoginController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-01-14
 *//*


@Slf4j
@RequiredArgsConstructor

@RestController
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();


    @PostMapping("/login")
    public Authentication login(@Validated @RequestBody LoginRequest reqDto
            , HttpServletRequest request
            , HttpServletResponse response) {

        UsernamePasswordAuthenticationToken token
                = UsernamePasswordAuthenticationToken.unauthenticated(reqDto.getUsername(), reqDto.getPassword());

        Authentication authenticate = authenticationManager.authenticate(token);
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        securityContext.setAuthentication(authenticate);
        SecurityContextHolder.getContextHolderStrategy().setContext(securityContext);

        securityContextRepository.saveContext(securityContext,request, response);

        return authenticate;
    }
}
*/
