/*
package com.business.security.common.config.basic.rememberme;

import com.business.security.common.config.basic.httpBasic.CustomAuthenticationEntryPoint;
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
 * <b> SecurityRememberMeConfig </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2024-08-13
 *//*


@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityRememberMeConfig {
    public static final String SECURITY_FILTER_CHAIN_NAME = "security-filter-chain";

    @Bean(SECURITY_FILTER_CHAIN_NAME)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .rememberMe(rememberMeConfigurer ->
                                rememberMeConfigurer
                                        .alwaysRemember(true) // 항상 기억하기 인증을 활성화 시킴(체크박스 없이도)
                                        .tokenValiditySeconds(3600) // 토큰 유지시간 (밀리세컨드)
                                        .userDetailsService(userDetailsService())
                                        .rememberMeParameter("remember")
                                        .rememberMeCookieName("remember")
                                        .key("myKey-security")
                        )
        ;

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
