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
                                                                  // false 일때는 인증 전에 요청했던 페이지로 redirect한다.
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
추가적으로 defaultSuccessUrl() 과 failureHandler()  API는 내부적으로:   
```java 
    public final T defaultSuccessUrl(String defaultSuccessUrl) {
        return this.defaultSuccessUrl(defaultSuccessUrl, false);
    }

    public final T defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(defaultSuccessUrl);
        handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
        this.defaultSuccessHandler = handler;
        return this.successHandler(handler);
    }

public final T failureUrl(String authenticationFailureUrl) {
    T result = this.failureHandler(new SimpleUrlAuthenticationFailureHandler(authenticationFailureUrl));
    this.failureUrl = authenticationFailureUrl;
    return result;
}

public final T failureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
    this.failureUrl = null;
    this.failureHandler = authenticationFailureHandler;
    return this.getSelf();
}
```
**successHandler** 와 **failureHandler**를 호출해서 우리가 지정한 URL 로 redirect 하게된다.  

이때 사용자가 failureHandler() 와 successHandler() API 를통해서 사용자 정의 핸들러를 지정한경우 이 사용자정의 핸들러가 우선순위가 더 높다.  
  
### 초기화 과정
formLogin() API를 후출하는 경우 :    
```java
    public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
        return (FormLoginConfigurer)this.getOrApply(new FormLoginConfigurer());
    }


```
코드를 확인해 보면 new FormLoginConfigurer() 객체를 생성하는 것을 볼 수 있다:  
```java 
    public FormLoginConfigurer() {
        super(new UsernamePasswordAuthenticationFilter(), (String)null);
        this.usernameParameter("username");
        this.passwordParameter("password");
    }
```
기본 생성자에서 인증에 필요한 필터인 **UsernamePasswordAuthenticationFilter**를 생성해서 부모 클레스에 전달하고 기본적은 username 과 password의 명을 설정한다.  
  
부모 클레스인 **AbstractAuthenticationFilterConfigurer** 를 확인해보면 스프링 시큐리티에서 기본적으로 설정하는 기본 로그인 페이지 경로와 핸들러등이 설정되는 것을 확인할 수 있고 configurer 클레스에서 가장 중요한 메서드인 configure() 메서드와 초기화 메서드 init()을 확인해보자  
  
init:  
```java 
    public void init(B http) throws Exception {
        this.updateAuthenticationDefaults();
        this.updateAccessDefaults(http);
        this.registerDefaultAuthenticationEntryPoint(http);
    }

protected final void updateAuthenticationDefaults() {
    if (this.loginProcessingUrl == null) { // 로그인 페이지 URL
        this.loginProcessingUrl(this.loginPage);
    }

    if (this.failureHandler == null) { // 실패 처리 핸들러
        this.failureUrl(this.loginPage + "?error");
    }

    LogoutConfigurer<B> logoutConfigurer = (LogoutConfigurer)((HttpSecurityBuilder)this.getBuilder()).getConfigurer(LogoutConfigurer.class);
    if (logoutConfigurer != null && !logoutConfigurer.isCustomLogoutSuccess()) {
        logoutConfigurer.logoutSuccessUrl(this.loginPage + "?logout");
    }

}
```  

configure:  
```java 
 public void configure(B http) throws Exception {
        PortMapper portMapper = (PortMapper)http.getSharedObject(PortMapper.class);
        if (portMapper != null) {
            this.authenticationEntryPoint.setPortMapper(portMapper);
        }

        RequestCache requestCache = (RequestCache)http.getSharedObject(RequestCache.class);
        if (requestCache != null) {
            this.defaultSuccessHandler.setRequestCache(requestCache);
        }

        this.authFilter.setAuthenticationManager((AuthenticationManager)http.getSharedObject(AuthenticationManager.class)); //위에서 생성된 UsernamePasswordAuthenticationFilter 필터가 전달
        this.authFilter.setAuthenticationSuccessHandler(this.successHandler);
        this.authFilter.setAuthenticationFailureHandler(this.failureHandler);
        if (this.authenticationDetailsSource != null) {
            this.authFilter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
        }

        SessionAuthenticationStrategy sessionAuthenticationStrategy = (SessionAuthenticationStrategy)http.getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            this.authFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }

        RememberMeServices rememberMeServices = (RememberMeServices)http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            this.authFilter.setRememberMeServices(rememberMeServices);
        }

        SecurityContextConfigurer securityContextConfigurer = (SecurityContextConfigurer)http.getConfigurer(SecurityContextConfigurer.class);
        if (securityContextConfigurer != null && securityContextConfigurer.isRequireExplicitSave()) {
            SecurityContextRepository securityContextRepository = securityContextConfigurer.getSecurityContextRepository();
            this.authFilter.setSecurityContextRepository(securityContextRepository);
        }

        this.authFilter.setSecurityContextHolderStrategy(this.getSecurityContextHolderStrategy());
        F filter = (AbstractAuthenticationProcessingFilter)this.postProcess(this.authFilter);
        http.addFilter(filter);
    }
```