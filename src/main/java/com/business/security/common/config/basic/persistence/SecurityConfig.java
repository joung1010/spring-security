/*
package com.business.security.common.config.basic.persistence;

import com.business.security.common.config.basic.authentication.userDetailService.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

*/
/**
 * <b> SecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-11-05
 *//*

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = managerBuilder.build();

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/login").permitAll()
                        .anyRequest().authenticated()
                )
//                .securityContext(security -> security.requireExplicitSave(false))
                .formLogin(Customizer.withDefaults())
                .authenticationManager(authenticationManager)
                .addFilterBefore(customPersistenceAuthenticationFilter(http,authenticationManager), UsernamePasswordAuthenticationFilter.class)
        ;
        return http.build();
    }

    public CustomPersistenceAuthenticationFilter customPersistenceAuthenticationFilter(HttpSecurity http
            , AuthenticationManager authenticationManager) throws Exception {

        CustomPersistenceAuthenticationFilter filter = new CustomPersistenceAuthenticationFilter(http);
        filter.setAuthenticationManager(authenticationManager);

        return filter;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailService();
    }


}
*/
