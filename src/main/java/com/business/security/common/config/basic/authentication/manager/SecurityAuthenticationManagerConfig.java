package com.business.security.common.config.basic.authentication.manager;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

/**
 * <b> SecurityAuthenticationManagerConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-09-03
 */
@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityAuthenticationManagerConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = builder.build();

        //만약 다른곳에서 build() 한다음에 AuthenticationManager 를 가져올때는 다시 build()하는 것이 아니라 getObject()를 통해서 가져온다.
//        AuthenticationManager authenticationManager = builder.getObject();



        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/","/api/login").permitAll()
                        .anyRequest().authenticated())
                .authenticationManager(authenticationManager)
                .addFilterBefore(customFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
        ;

        return http.build();
    }

    public CustomAuthenticationFilter customFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }
}
