package com.business.security.business.endpoint.integration;

import com.business.security.business.endpoint.integration.model.MemberDto;
import com.business.security.common.config.basic.integration.annotation.CurrentUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * <b> IntegrationServletController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-21
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "integration-2", matchIfMissing = false)

@RequestMapping("/mvc")
@RestController
public class IntegrationSpringMvcController {

    AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();

    @GetMapping("")
    public String index(){
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        return trustResolver.isAnonymous(authentication) ? "anonymous" : "authentication";

    }
    @GetMapping("/user")
    public User user(@AuthenticationPrincipal User user){

        return user;
    }

    @GetMapping("/db")
    public String db(@AuthenticationPrincipal(expression = "username") String user){
        return user;
    }
    @GetMapping("/admin")
    public String admin(@CurrentUser String username){
        return username;
    }

    @GetMapping("/currentUser")
    public String currentUser(@CurrentUser String username){

        return username;
    }

}
