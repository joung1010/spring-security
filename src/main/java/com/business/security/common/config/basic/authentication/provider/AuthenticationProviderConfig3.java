package com.business.security.common.config.basic.authentication.provider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


/**
 * <b> AuthenticationProviderConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-10-22
 */


@Slf4j
@EnableWebSecurity
@Configuration
public class AuthenticationProviderConfig3 {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {



        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated())
                .authenticationProvider(customAuthenticationProvider())
                .authenticationProvider(customAuthenticationProvider2())
        ;
        return http.build();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider() {
        //parent 에 추가
        return new CustomAuthenticationProvider();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider2() {
        //parent 에 추가
        return new CustomAuthenticationProvider2();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }

}

