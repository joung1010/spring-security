package com.business.security.business.endpoint.integration;

import com.business.security.business.endpoint.integration.model.MemberDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
@ConditionalOnProperty(value = "security.type", havingValue = "integration-1", matchIfMissing = false)

@RequestMapping("/servlet")
@RestController
public class IntegrationServletController {
    @GetMapping("/")
    public String index(HttpServletRequest request){
        return "index";
    }
    @GetMapping("/user")
    public String user(){
        return "user";
    }
    @GetMapping("/db")
    public String db(){
        return "db";
    }
    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/login")
    public String login(HttpServletRequest request, MemberDto memberDto) throws ServletException, IOException {
        request.login(memberDto.getUsername(), memberDto.getPassword());
        log.info("login is successful");

        return "login";
    }

    @GetMapping("/users")
    public List<MemberDto> users(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        boolean authenticate = request.authenticate(response);
        if (authenticate) {
            return List.of(new MemberDto("user","1111"));
        }

        return Collections.emptyList();
    }
}
