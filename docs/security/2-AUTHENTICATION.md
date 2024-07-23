# 인증 프로세스
## 폼인증
HTTP 기반의 폼 로그인 인증 메커니즘을 활성화하는 API로 사용자 인증을 위한 사용자 정의 로그인 페이지를 쉽게 구현할 수 있다. 또한 기본적으로 스프링 시큐리티가 제공하는 기본 로그인 페이지를 이용하면 사용자 이름과 비밀번호 필드가 포함된 간단한 폼 로그인 양식을 제공한다.  
  
사용자는 웹 폼을 통해 자격 증명(사용자 이름 및 비밀번호)을 제공하고 스프링 시큐리티는 HttpServletRequest 에서 이 값을 읽어온다.  
```
1. 클라이언트 요청 (Request Get)
   └─────────────→
2. 필터 체인 통과
   └─────────────→
3. 권한 검사 (AuthorizationFilter)
   └─────────────→
4. 접근 예외 발생 (AcessDeniedException)
   └─────────────→
5. 예외 처리 (ExceptionTranslationFilter)
   └─────────────→
6. 로그인 페이지로 리다이렉트
   └─────────────→
7. 로그인 페이지에서 인증 시도
   └─────────────→
8. 서버 도착
   └─────────────→
9. 인증 처리
   └─── UsernamePasswordAuthenticationFilter
   └─── AuthenticationManager
   └─── UserDetailsService
   └─── AuthenticationProvider
   └─────────────→
10. 인증 성공 시
    └─── SecurityContextHolder에 인증 정보 저장
    └─── AuthenticationSuccessHandler 호출
   └─────────────→
11. 인증 실패 시
    └─── AuthenticationFailureHandler 호출
```  

### formLogin()
FormLoginConfigurer 설정 클레스를 통해 설정할 수 있다. 내부적으로는 **`UsernamePasswordAuthenticationFilter`** 가 생성되어 처리를 담당한다.  
  
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated()  // 모든 요청에 대해 인증 필요
                )
                .formLogin(httpSecurityFormLoginConfigurer ->
                        httpSecurityFormLoginConfigurer
                                .loginPage("/login")  // 사용자 정의 로그인 페이지 URL
                                .loginProcessingUrl("/perform_login")  // 로그인 폼의 action URL(사용자 이름과 비밀번호를 검증할 URL 지점)
                                .defaultSuccessUrl("/home", true)  // 로그인 성공 후 리다이렉트할 기본 URL(true 이면 무조건 지정된 위치로 이동 기본 false)
                                .failureUrl("/login?error=true")  // 로그인 실패 시 리다이렉트할 URL
                                .usernameParameter("username")  // 로그인 폼에서 사용자 이름 입력 필드 이름
                                .passwordParameter("password")  // 로그인 폼에서 비밀번호 입력 필드 이름
                                .failureHandler(AuthenticationFailureHandler )  // 사용자 정의 실패 핸들러(AuthenticationFailureHandler) 지정
                                                                                // 기본 값은 SimpleUrlAuthenticationFailureHandler 를 사용 /login?error로 리다이렉트
                                .successHandler(AuthenticationSuccessHandler )  // 사용자 정의 성공 핸들러(AuthenticationSuccessHandler) 지정
                                                                                // 기본 값은 SavedRequestAwareAuthenticationSuccessHandler
                                .permitAll()  // failureUrl(), loginPage(), loginProcessUrl 에 대한 URL 에 모든 사용자 접근 허용
                );
        return http.build();
    }
}
```
