/*
package com.business.security.common.config.basic.annonymous;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

*/
/**
 * <b> SecurityAnonymousConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-08-20
 *//*


@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityAnonymousConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests(auth -> auth
                        .requestMatchers("/anonymous").hasRole("GUEST")
                        .requestMatchers("/anonymousContext", "/authentication").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .anonymous(anonymous -> anonymous
                        .principal("guest")
                        .authorities("ROLE_GUEST")
                );

        return http.build();
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
*/
