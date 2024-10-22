package com.business.security.common.config.basic.authentication.provider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
public class AuthenticationProviderConfig2 {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http
            , AuthenticationManagerBuilder builder
            , AuthenticationConfiguration configuration ) throws Exception {

        // 기존 HttpSecurity가 가지고있는 AuthenticationMangerBuilder를 가져옴
        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        // providers에 우리가 만든 커스텀 provider를 추가
        managerBuilder.authenticationProvider(customAuthenticationProvider());
        // 기존 parent에 설정되어있던 DaoAuthenticationProvider를 원복
        ProviderManager providerManager = (ProviderManager)configuration.getAuthenticationManager();
        providerManager.getProviders().remove(0); // 우리가 만든 Provider를 제거

        builder.authenticationProvider(new DaoAuthenticationProvider());//자동설정 Provider 추가

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated())
        ;
        ;
        return http.build();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider() {
        //parent 에 추가
        return new CustomAuthenticationProvider();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }

}
