package com.business.security.common.config.basic.authorization;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * <b> AuthorityAuthorizationManagerSecurityConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-07-01
 */

@Slf4j
@EnableWebSecurity
@ConditionalOnProperty(value = "security.type", havingValue = "authorization-manager", matchIfMissing = false)

@Configuration
public class AuthorityAuthorizationManagerSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {


        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/","/login").permitAll()
                        .requestMatchers("/manager/user").hasRole("USER")
                        .requestMatchers("/manager/db").access(new WebExpressionAuthorizationManager("hasRole('DB')"))
                        .requestMatchers("/manager/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }


    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails manager = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN","SECURE").build();
        return new InMemoryUserDetailsManager(user, manager, admin);
    }
}
