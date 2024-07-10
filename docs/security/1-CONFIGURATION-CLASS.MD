## 설정 클레스
### SecurityBuilder 와 SecurityConfigurer
**SecurityBuilder** 는 빌더 클래스로서 **웹 보안을 구성하는 빈 객체와 설정 클래스들을 생성**하는 역할이다. 대표적으로 `WebSecurity`, `HttpSecurity`가 있다.  

**SecurityConfigurer**는 Http 요청과 관련된 **보안처리를 담당하는 필터**를 `생성`, `초기화` 설정에 관여한다.  

**SecurityBuilder** 는 **SecurityConfigurer** 를 참조하고 있으며 인증 및 인가 초기화 작업은 **SecurityConfigurer** 에 의해 진행된다.
### SecurityBuilder

- **역할**: `SecurityBuilder`는 스프링 시큐리티의 핵심 인터페이스 중 하나로, 보안 객체를 구성하는 빌더 패턴을 제공합니다. 주로 보안 설정을 만들고 조립하는 데 사용됩니다.
- **주요 메서드**:
    - `build()`: 최종 보안 객체를 구성하고 반환합니다.
    - `setSharedObject(Class<T> sharedType, T object)`: 공유 객체를 설정합니다.
    - `getSharedObject(Class<T> sharedType)`: 공유 객체를 가져옵니다.
    - `getOrBuild()`: 빌더가 생성되었으면 해당 객체를 반환하고, 아니면 새로 빌드하여 반환합니다.

### SecurityConfigurer

- **역할**: `SecurityConfigurer`는 보안 설정을 구성하는 데 사용되는 인터페이스입니다. 보안 설정을 정의하고 이를 `SecurityBuilder`와 통합할 수 있습니다.
- **주요 메서드**:
    - `init(B builder)`: 초기화 작업을 수행합니다.
    - `configure(B builder)`: 실제 보안 설정을 적용합니다.
    - `setBuilder(B builder)`: 빌더를 설정합니다.

### 클래스 상속 관계도

아래는 `SecurityBuilder`와 `SecurityConfigurer`의 상속 관계 및 주요 관련 클래스들을 계층 구조로 나타낸 것입니다.

```scss
scss코드 복사
SecurityBuilder (인터페이스)
│
├── AbstractConfiguredSecurityBuilder (추상 클래스)
│   │
│   ├── WebSecurity (구체 클래스)
│   │
│   └── HttpSecurity (구체 클래스)
│
SecurityConfigurer (인터페이스)
│
├── SecurityConfigurerAdapter (추상 클래스)
│   │
│   ├── WebSecurityConfigurerAdapter (추상 클래스)
│   │   │
│   │   ├── DefaultSecurityConfig (구체 클래스 - 사용자 정의 설정)
│   │   └── 여러 사용자 정의 구체 클래스들
│   │
│   └── 여러 사용자 정의 구체 클래스들
│
└── 다양한 SecurityConfigurer 인터페이스 구현 클래스들

```

### 주요 클래스 간의 관계 설명

1. **SecurityBuilder** 인터페이스는 다양한 보안 구성 요소를 빌드하기 위한 핵심 인터페이스입니다.
2. **AbstractConfiguredSecurityBuilder**는 `SecurityBuilder` 인터페이스를 구현한 추상 클래스입니다. 주로 보안 구성의 기본 기능을 제공하며, 이를 확장하여 구체적인 보안 빌더가 만들어집니다.
3. **WebSecurity**와 **HttpSecurity**는 각각 웹 보안과 HTTP 보안 설정을 위한 구체적인 빌더 클래스입니다.
4. **SecurityConfigurer** 인터페이스는 보안 설정을 구성하는 데 사용되며, 이를 구현한 클래스들은 보안 설정의 세부 사항을 정의합니다.
5. **SecurityConfigurerAdapter**는 `SecurityConfigurer` 인터페이스를 구현한 추상 클래스입니다. 이 클래스는 주로 초기화 및 기본 설정을 처리하며, 이를 확장하여 사용자 정의 보안 설정을 만듭니다.
6. **WebSecurityConfigurerAdapter**는 `SecurityConfigurerAdapter`를 확장한 추상 클래스로, 웹 보안 설정을 위한 기본 구성을 제공합니다. 이 클래스를 확장하여 사용자 정의 보안 설정을 정의할 수 있습니다.
7. **DefaultSecurityConfig**는 사용자 정의 보안 설정의 예시로, `WebSecurityConfigurerAdapter`를 확장하여 구체적인 보안 설정을 정의합니다.

  
### 스프링 Security의 자동설정
```scss
scss코드 복사
AutoConfiguration (자동 설정)
│
├── SecurityAutoConfiguration
│   ├── SpringBootWebSecurityConfiguration
│   │   ├── WebSecurityConfigurerAdapter
│   │   │   ├── DefaultSecurityConfig
│   │   │   └── CustomSecurityConfigurer
│   │   └── 여러 WebSecurityConfigurer 구현 클래스들
│   │
│   └── UserDetailsServiceAutoConfiguration
│
SecurityBuilder (인터페이스)
│
├── AbstractConfiguredSecurityBuilder
│   ├── WebSecurity
│   └── HttpSecurity
│
SecurityConfigurer (인터페이스)
│
├── SecurityConfigurerAdapter
│   └── WebSecurityConfigurerAdapter
│       ├── DefaultSecurityConfig
│       └── 여러 사용자 정의 설정 클래스들
│
└── 다양한 SecurityConfigurer 구현 클래스들

```
### 흐름 설명

1. **자동 설정 시작**:
    - 스프링 부트가 시작되면 **SecurityAutoConfiguration**이 로드됩니다. 이 클래스는 **SpringBootWebSecurityConfiguration**을 포함한 다양한 보안 구성 클래스를 가져와 초기화합니다.
2. **SecurityBuilder 생성**:
    - **SpringBootWebSecurityConfiguration**은 `SecurityBuilder`(주로 `HttpSecurity`와 `WebSecurity`)를 생성합니다.
3. **SecurityConfigurer 초기화 및 구성**:
    - **SpringBootWebSecurityConfiguration**은 등록된 모든 **WebSecurityConfigurerAdapter**를 가져와 `init`과 `configure` 메서드를 호출합니다.
        - `init(B builder)`: 초기화 작업을 수행합니다.
        - `configure(B builder)`: 실제 보안 설정을 적용합니다.
4. **보안 설정 적용**:
    - **SecurityBuilder**는 `SecurityConfigurer`에서 제공하는 설정을 기반으로 최종 보안 객체를 빌드합니다.
    - `SecurityBuilder.build()` 메서드를 통해 최종 보안 구성이 완료됩니다.
5. **필터 생성**
   - SecurityBuilder 를 통해서 생성된 HeaderConfigurer, HttpBasicConfigurer 등을 생성하고 각 클레스 마다 해당하는 필터를 초기화 및 설정한다.

이 흐름을 통해 스프링 시큐리티는 자동으로 보안 설정을 초기화하고 구성하여 애플리케이션이 실행될 때 필요한 보안 기능을 제공합니다.
  
### 실습
스프링 부트를 동작하면 자동설정 클레스가 기본 인증, 인가와 관련된 설정을 하게된다.  
자동설정 에서 해당 설정을 생성한다.
`HttpSecurityConfiguration`:  
```java
    @Bean({"org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration.httpSecurity"})
    @Scope("prototype")
    HttpSecurity httpSecurity() throws Exception {
        LazyPasswordEncoder passwordEncoder = new LazyPasswordEncoder(this.context);
        AuthenticationManagerBuilder authenticationBuilder = new DefaultPasswordEncoderAuthenticationManagerBuilder(this.objectPostProcessor, passwordEncoder);
        authenticationBuilder.parentAuthenticationManager(this.authenticationManager());
        authenticationBuilder.authenticationEventPublisher(this.getAuthenticationEventPublisher());
        HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, this.createSharedObjects());
        WebAsyncManagerIntegrationFilter webAsyncManagerIntegrationFilter = new WebAsyncManagerIntegrationFilter();
        webAsyncManagerIntegrationFilter.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
        http.csrf(Customizer.withDefaults()).addFilter(webAsyncManagerIntegrationFilter).exceptionHandling(Customizer.withDefaults()).headers(Customizer.withDefaults()).sessionManagement(Customizer.withDefaults()).securityContext(Customizer.withDefaults()).requestCache(Customizer.withDefaults()).anonymous(Customizer.withDefaults()).servletApi(Customizer.withDefaults()).apply(new DefaultLoginPageConfigurer());
        http.logout(Customizer.withDefaults());
        this.applyCorsIfAvailable(http);
        this.applyDefaultConfigurers(http);
        return http;
    }

```
> @Scope("prototype")  
> 빈을 요청할 때마다 새로운 인스턴스를 생성하도록 스프링 컨테이너에 지시합니다.
  
기본 설정 부분을 따라 들어가 보면  
```java
 http.csrf(Customizer.withDefaults()).addFilter(webAsyncManagerIntegrationFilter).exceptionHandling(Customizer.withDefaults()).headers(Customizer.withDefaults()).sessionManagement(Customizer.withDefaults()).securityContext(Customizer.withDefaults()).requestCache(Customizer.withDefaults()).anonymous(Customizer.withDefaults()).servletApi(Customizer.withDefaults()).apply(new DefaultLoginPageConfigurer());
        http.logout(Customizer.withDefaults());
```
  
```java
    public HttpSecurity csrf(Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {
        ApplicationContext context = this.getContext();
        csrfCustomizer.customize((CsrfConfigurer)this.getOrApply(new CsrfConfigurer(context)));
        return this;
    }
```
```java
public final class CsrfConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<CsrfConfigurer<H>, H> {
    //...
}
``` 
참조 하고 있는 Configurer 클레스를 계속 타고가다보면 결국 SecurityConfigurer 클레스가 나온다.  
그래서 이 해당 설정 클레스를 지금 생성하면서 `this.getOrApply` 해당 메서드를 통해서 생서되는 설정 클레스를 어느 곳에다가 적용하고 있는 것을 볼 수 있다.  
  
그래서 이러한 과정들을 필요한 필터에 맞게 설정을 추가하여 `SecurityBuilder` 를 통해 생성한다.  
  
이렇게 생성된 설정클레스 HttpSecurity를 `SpringBootWebSecurityConfiguration` 에서 해당 빈을 주입 받아서 처리하게 된다.  
```java
    @ConditionalOnDefaultWebSecurity
    static class SecurityFilterChainConfiguration {
        SecurityFilterChainConfiguration() {
        }

        @Bean
        @Order(2147483642)
        SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests((requests) -> {
                ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated();
            });
            http.formLogin(Customizer.withDefaults());
            http.httpBasic(Customizer.withDefaults());
            return (SecurityFilterChain)http.build();
        }
    }
```
  
이렇게 설정파일 빈을 만들고 `SecurityFilterChain` 최종적으로 build 를 하게 되면 각 설정 클레스 안에 있는 초기화(init) 와 이를 적용(configure) 메서드를 호출하게 된다.  
  
```java
    public final O build() throws Exception {
        if (this.building.compareAndSet(false, true)) {
            this.object = this.doBuild();
            return this.object;
        } else {
            throw new AlreadyBuiltException("This object has already been built");
        }
    }
```
this.doBuild():
```java
    protected final O doBuild() throws Exception {
        synchronized(this.configurers) {
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.INITIALIZING;
            this.beforeInit();
            this.init(); // 초기화
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.CONFIGURING;
            this.beforeConfigure();
            this.configure(); // 설정 적용
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILDING;
            O result = this.performBuild();
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILT;
            return result;
        }
    }
```
  
## WebSecurity And HttpSecurity
  
### HttpSecurity (SecurityBuilder 의 구현체)
HttpSecurityConfiguration 에서 HttpSecurity 를 생성하고 초기화를 진행한다 해당 클레스는 보안에 필요한 각 설정 클레스와 필터들을 생성하고 최종적으로는 **`SecurityFilterChain`** 빈을 생성한다.  

HttpSecurity를 통해 **인증**, **인가**, 세션 관리, CSRF 보호 등의 다양한 보안 기능을 설정할 수 있습니다.  
  
### HttpSecurity 구성 다이어 그램
```scss

+--------------------------------------------+  +------------------------------------------------------+
|               HttpSecurity                 |  |                  Security Configuration              |
|                                            |  |------------------------------------------------------|
|  +-----------------+  +------------------+ |  | - WebSecurityConfigurerAdapter                       |
|  | Authentication  |  | Authorization    | |  | - @EnableWebSecurity                                 |
|  |                 |  |                  | |  | - HttpSecurity configuration                         |
|  | - formLogin()   |  | - antMatchers()  | |  +-------------------|----------------------------------+
|  | - httpBasic()   |  | - anyRequest()   | |                      |
|  +-----------------+  +------------------+ |                      v
|                                            |  +------------------------------------------------------+
|  +---------------+  +--------------------+ |  |                  SecurityFilterChain                 |
|  | CSRF Protection|  | Session Management| |  |------------------------------------------------------|
|  |               |  |                    | |  | - Configured with HttpSecurity settings              |
|  | - csrf()      |  | - sessionCreation  | |  | - Multiple security filters                          |
|  +---------------+  +--------------------+ |  +-------------------|----------------------------------+
|                                            |                      |
|  +---------------------+                   |                      v
|  | Exception Handling  |                   |  +------------------------------------------------------+
|  |                     |                   |  |                  Filter Chain                        |
|  | - authenticationEntry|                  |  |------------------------------------------------------|
|  | - accessDeniedHandler|                  |  | - SecurityContextPersistenceFilter                   |
|  +---------------------+                   |  | - UsernamePasswordAuthenticationFilter               |
+--------------------------------------------+  | - BasicAuthenticationFilter                          |
                                                 | - CsrfFilter                                         |
                                                 | - LogoutFilter                                       |
                                                 | - ExceptionTranslationFilter                         |
                                                 | - FilterSecurityInterceptor                          |
                                                 +-------------------|----------------------------------+
                                                                       |
                                                                       v
                                                 +------------------------------------------------------+
                                                 |                  Request Handling                    |
                                                 |------------------------------------------------------|
                                                 | - HTTP requests pass through the filter chain        |
                                                 | - Filters apply security logic                       |
                                                 | - Requests are processed and responses are returned  |
                                                 +------------------------------------------------------+

```
  
### SecurityFilterChain 
보안 필터들을 특정 순서대로 구성하여 HTTP 요청과 응답을 처리하는 역할을 담당한다. **SecurityFilterChain**은 인터페이스이며 기본 구현체로는 **DefaultSecurityFilterChain** 이 있다.  

HTTP 요청이 들어오면 SecurityFilterChain은 첫 번째 필터부터 마지막 필터까지 순차적으로 요청을 처리합니다. 각 필터는 요청을 가로채고 필요한 보안 작업을 수행한 후 다음 필터로 요청을 전달합니다. 만약 특정 필터에서 요청이 차단되거나 예외가 발생하면 그 즉시 필터 체인이 중단되고 적절한 응답이 반환됩니다.  

### 1. **`getFilters`**

```java
List<Filter> getFilters();

```

- **설명**: 이 메서드는 필터 체인에 포함된 `Filter` 객체들의 리스트를 반환합니다.
- **반환값**:
    - `List<Filter>`: 필터 체인에 포함된 필터들의 리스트.
### 2. **`matches`**

```java
boolean matches(HttpServletRequest request);

```

- **설명**: 이 메서드는 주어진 HTTP 요청이 이 **필터 체인에 매핑되는지 여부**를 확인합니다.
- **매개변수**:
    - `HttpServletRequest request`: 들어오는 HTTP 요청.
- **반환값**:
    - `boolean`: 요청이 이 필터 체인에 매핑되는 경우 `true`, 그렇지 않은 경우 `false`.
  
### WebSecurity (SecurityBuilder 의 구현체)
WebSecurityConfiguration 에서 WebSecurity를 생성하고 초기화한다. WebSecurity 는 HttpSecurity 에서 생성한 SecurityFilterChain 빈을 SecurityBuilder 에 저장하고 build() 되었을때 SecurityBuilder 에서 SecurityFilterChain을 꺼내어 FilterChainProxy 생성자에 전달한다.  


### WebSecurity 초기화 및 동작 흐름

```scss
+-------------------------------+
| Spring Application Context    |
|  +-------------------------+  |
|  | WebSecurityConfiguration |  |
|  +-------------------------+  |
+-------------------------------+
                |
                v
+-------------------------------+
| WebSecurity                  |
|  +-------------------------+  |
|  | HttpSecurity            |  |
|  +-------------------------+  |
+-------------------------------+
                |
                v
+----------------------------------------+
| HttpSecurity                           |
|  +----------------------------------+  |
|  | URL Authorization Rules          |  |
|  | Login/Logout Configuration       |  |
|  | CSRF Protection                  |  |
|  +----------------------------------+  |
|  | SecurityFilterChain (Bean)       |  |
|  +----------------------------------+  |
+----------------------------------------+
                |
                v
+----------------------------------------+
| SecurityBuilder                        |
|  +----------------------------------+  |
|  | Store SecurityFilterChain        |  |
|  +----------------------------------+  |
|  | Build SecurityFilterChain        |  |
|  +----------------------------------+  |
+----------------------------------------+
                |
                v
+----------------------------------------+
| FilterChainProxy                       |
|  +----------------------------------+  |
|  | SecurityFilterChain              |  |
|  +----------------------------------+  |
+----------------------------------------+
                |
                v
+-------------------------+
| HTTP Request            |
|  /secure/data           |
+-------------------------+
                |
                v
+-------------------------+
| FilterChainProxy        |
|  +-------------------+  |
|  | Auth Filter       |  |
|  +-------------------+  |
|  | CSRF Filter       |  |
|  +-------------------+  |
|  | Logout Filter     |  |
|  +-------------------+  |
+-------------------------+
                |
                v
+-------------------------+
| HTTP Response           |
|  (Authenticated Data)   |
+-------------------------+

```
### 설명
1. **Spring Application Context 초기화**: Spring 애플리케이션이 시작되고, `WebSecurityConfiguration` 빈이 생성되어 초기화됩니다.
2. **WebSecurityConfiguration**: `WebSecurityConfiguration`에서 `WebSecurity`가 생성되고 초기화됩니다.
3. **HttpSecurity 설정**: `HttpSecurity` 설정이 적용되고, `SecurityFilterChain` 빈이 생성됩니다.
4. **SecurityFilterChain 빈 저장**: 생성된 `SecurityFilterChain` 빈이 `SecurityBuilder`에 저장됩니다.
5. **SecurityBuilder 빌드**: `SecurityBuilder`가 빌드되면서 `SecurityFilterChain`을 가져옵니다.
6. **FilterChainProxy 생성**: `SecurityFilterChain`이 `FilterChainProxy` 생성자에 전달되어 `FilterChainProxy`가 생성됩니다.
7. **HTTP 요청 처리**: 요청이 `FilterChainProxy`를 통해 필터링되고, 각 필터가 순차적으로 실행되어 인증 및 인가 검사가 수행됩니다. 최종적으로 응답이 반환됩니다.
  
즉 `HttpSecurity` 가 여러설정들을 가지고 `SecurityFilterChain` 빈을 생성한다. 이렇게 생성된 필터들을 Client 에서 요청이 들어오면 해당 요청에 맞는 필터를 꺼내서 사용해야 하는데 이 작업을 `SecurityFilterChain` 이 직접 수행 하지 않고 `FilterChainProxy` 빈이 그 작업을 수행하게 된다.

  
