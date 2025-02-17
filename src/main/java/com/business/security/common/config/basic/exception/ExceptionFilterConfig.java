package com.business.security.common.config.basic.exception;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;


@Slf4j
@EnableWebSecurity
@Configuration
public class ExceptionFilterConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN") //인증 받았어도 해당 특정 권한이 있어야 접근가능
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .exceptionHandling(ex -> ex
/*                        .authenticationEntryPoint(new AuthenticationEntryPoint() {
                                                      @Override
                                                      public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                                                          log.info("기본적으로 인증을 재시도 할 수 있는 페이지로===");
                                                          log.info(authException.getMessage());

                                                          response.sendRedirect("/login"); //기본적인 페이지를 생성 하지 않는다.
                                                      }
                                                  }

                        )*/
                        .accessDeniedHandler(new AccessDeniedHandler() {
                            @Override
                            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                                log.info("exception {}", accessDeniedException.getLocalizedMessage());

                                response.sendRedirect("/denied");
                            }
                        })
                )
        ;

        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
