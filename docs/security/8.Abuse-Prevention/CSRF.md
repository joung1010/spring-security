## CSRF(Cross-Site Request Forgery)란?

- **기본 개념**:

  CSRF는 사용자가 인증된 상태에서 악의적인 제3의 사이트가 사용자를 대신해 원치 않는 요청을 서버로 전송하도록 유도하는 공격입니다.

  이는 사용자의 브라우저가 자동으로 보낼 수 있는 인증 정보, 예를 들어 쿠키나 기본 인증 세션을 이용하여 사용자가 의도하지 않은 요청을 서버로 전송하게 만든다.

  예를 들어, 사용자가 은행 웹사이트에 로그인한 상태에서 악의적인 사이트에 접속하면, 해당 사이트가 사용자의 인증 정보를 이용해 돈을 이체하는 등의 요청을 보낼 수 있습니다.

- **주요 목적**:
    - **공격 시나리오 차단**: 사용자의 인증 정보를 탈취하지 않고도, 인증된 세션을 이용한 원치 않는 요청을 방지합니다.
    - **서버 안전성 강화**: 악의적인 요청을 사전에 차단하여 데이터 무결성과 보안을 유지합니다.
- **동작 방식**:

  CSRF 공격은 브라우저의 쿠키 자동 전송 기능을 악용합니다. 서버는 클라이언트의 요청이 올바른 출처에서 온 것인지, 즉 사용자가 실제로 요청을 의도했는지를 확인하기 위해 CSRF 토큰을 사용합니다.


---

## 1. CSRF 공격과 방어 기법

- **공격 시나리오**:
    - 사용자가 로그인된 상태에서, 악의적인 웹사이트가 숨겨진 폼이나 자바스크립트를 통해 서버에 요청을 보냅니다.
    - 브라우저는 자동으로 쿠키를 첨부하여 요청을 전송하므로, 서버는 해당 요청을 정상적인 것으로 판단할 수 있습니다.
- **방어 기법**:
    - **CSRF 토큰 사용**: 서버는 클라이언트에게 난수 기반의 토큰을 발급하고, 폼이나 AJAX 요청에 해당 토큰을 포함시킵니다.
    - **검증 과정**: 서버는 요청 시 전달된 토큰과 세션 또는 저장소에 보관된 토큰을 비교하여, 일치할 경우에만 요청을 처리합니다.
    - **Double Submit Cookie**: 쿠키와 요청 파라미터에 동일한 토큰 값을 담아 비교하는 방식도 사용됩니다.

---

## 2. Spring Security에서의 CSRF 설정

- **기본 동작**:

  Spring Security는 **기본적으로 CSRF 보호를 활성화**합니다.

  폼 기반 웹 애플리케이션에서는 각 HTML 폼에 **CSRF 토큰이 자동 포함**되며, **POST, PUT, DELETE** 등 **상태를 변경하는 요청 시 토큰 검증을 수행**합니다.

  토큰은 서버에 의해 생성되어 클라이언트의 세션에 저장되고, 폼을 통해 서버로 송되는 모든 변경 요청에 포함되어야 하며 서버는 이 토큰을 검증하여 요청의 유효성을 확인한다.

  중요한 점은 실제 CSRF 토큰이 **브라우저에 의해 자동으로 포함되지 않는 요청** 부분에 위치해야 한다. 즉, **HTTP 매개변수나** **헤더**에 실제 CSRF 토큰을 요구하는 것이 CSRF 공격을 방지하는데 효과적이다.

- **CSRF 비활성화**:

  REST API와 같이 무상태(stateless) 애플리케이션에서는 CSRF 보호가 불필요한 경우가 많으므로, `csrf.disable()`로 비활성화할 수 있습니다.  
    
    CSRF 보호가 필요하지 않는 특정 엔드포인트만 비활성화 `csrf.ignoringRequestMatchers("/api/*")` 한다.


- **설정 포인트**:
    - **HttpSecurity.csrf()**: CSRF 관련 필터(기본적으로 `CsrfFilter`)가 필터 체인에 등록되어, 요청의 CSRF 토큰을 검증합니다.
    - **CsrfTokenRepository**: CSRF 토큰의 생성, 저장, 검증을 담당하는 전략 빈을 통해 토큰 관리가 이루어집니다.

---

## 3. 내부 동작 방식 및 CsrfFilter의 구현

### 3.1 CsrfFilter의 역할

- **토큰 생성 및 저장**:

  요청이 들어오면, `CsrfFilter`는 먼저 `CsrfTokenRepository`를 통해 현재 요청에 대한 CSRF 토큰을 로드합니다.

  토큰이 없으면 새로 생성하여 저장합니다.

- **토큰 검증**:

  상태 변경(POST, PUT, DELETE 등) 요청 시, 요청 파라미터나 헤더에 포함된 CSRF 토큰과 저장된 토큰을 비교합니다.

  불일치하면 `InvalidCsrfTokenException` 등을 발생시켜 요청을 차단합니다.

- **요청 속성 설정**:

  검증에 필요한 CSRF 토큰 정보를 요청 속성에 설정하여, 이후 처리(예: 뷰 렌더링)에서 활용할 수 있도록 합니다.


### 3.2 내부 소스 코드 관점 (개념적 예시)

아래는 `CsrfFilter`의 핵심 동작을 단순화하여 표현한 예시 코드입니다.

```java

public class CsrfFilter extends OncePerRequestFilter {

    private final CsrfTokenRepository tokenRepository;

    public CsrfFilter(CsrfTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1. 현재 요청에 대한 CSRF 토큰 로드
        CsrfToken csrfToken = tokenRepository.loadToken(request);

        // 2. 토큰이 없으면 새로 생성 후 저장
        if (csrfToken == null) {
            csrfToken = tokenRepository.generateToken(request);
            tokenRepository.saveToken(csrfToken, request, response);
        }

        // 3. 토큰 정보를 요청 속성에 설정 (예: 뷰 렌더링 시 활용)
        request.setAttribute(CsrfToken.class.getName(), csrfToken);

        // 4. 상태 변경 요청의 경우, 토큰 검증 수행
        if (isStateChangingRequest(request)) {
            String actualToken = obtainTokenFromRequest(request, csrfToken);
            if (!csrfToken.getToken().equals(actualToken)) {
                throw new InvalidCsrfTokenException(csrfToken, actualToken);
            }
        }

        // 5. 필터 체인 계속 진행
        filterChain.doFilter(request, response);
    }

    private boolean isStateChangingRequest(HttpServletRequest request) {
        String method = request.getMethod();
        return ("POST".equals(method) || "PUT".equals(method) ||
                "DELETE".equals(method) || "PATCH".equals(method));
    }

    private String obtainTokenFromRequest(HttpServletRequest request, CsrfToken csrfToken) {
        // 예: 요청 파라미터 또는 헤더에서 토큰 추출
        String token = request.getParameter(csrfToken.getParameterName());
        if (token == null) {
            token = request.getHeader(csrfToken.getHeaderName());
        }
        return token;
    }
}

```

> 내부 동작 설명:
>
> - `OncePerRequestFilter`를 상속하여, 한 요청당 한 번만 CSRF 검증이 수행되도록 보장합니다.
> - CSRF 토큰은 `CsrfTokenRepository`를 통해 관리되며, 이 저장소는 메모리, 세션, 쿠키 등 다양한 방식으로 구현할 수 있습니다.
> - 검증 로직은 **Chain of Responsibility** 패턴의 일부로, CSRF 필터가 다른 보안 필터와 함께 요청을 순차적으로 처리하면서, 요청의 안전성을 보장합니다.

---

## 4. Spring Security CSRF 설정 예제 (Spring Boot 3 / Spring Security 6+)

```java

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 기본적으로 CSRF 보호 활성화 (REST API의 경우 disable() 할 수 있음)
            .csrf(csrf -> csrf
                // 기본 CsrfTokenRepository를 사용하거나 커스터마이징 가능
                .csrfTokenRepository(CustomCsrfTokenRepository.withHttpOnlyFalse())
            )
            // 인가 설정 예시
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/login", "/error").permitAll()
                .anyRequest().authenticated()
            )
            // 폼 로그인 설정
            .formLogin(Customizer.withDefaults());

        return http.build();
    }
}

```

> 참고: REST API와 같이 무상태(stateless) 환경에서는 CSRF 보호가 필요 없으므로, .csrf(csrf -> csrf.disable())를 통해 비활성화할 수 있습니다.
>

---

## 최종 정리

1. **CSRF의 역할**:
    - 사용자가 인증된 상태에서 악의적인 사이트가 원치 않는 요청을 서버로 보내는 공격을 방지합니다.
2. **방어 기법**:
    - CSRF 토큰을 통해 요청이 합법적인지 검증하며, 이를 통해 보안을 강화합니다.
3. **Spring Security에서의 CSRF 처리**:
    - 기본적으로 `CsrfFilter`가 등록되어, 요청마다 토큰을 생성/검증합니다.
    - 토큰은 `CsrfTokenRepository`를 통해 관리되며, 상태 변경 요청 시 반드시 검증됩니다.
4. **내부 구현 소스 코드**:
    - `CsrfFilter`는 `OncePerRequestFilter`를 상속하여 한 요청 당 한 번만 실행됩니다.
    - 요청의 CSRF 토큰을 로드, 생성, 저장 및 검증하는 과정을 통해 안전한 요청만을 허용합니다.
5. **실제 설정 예제**:
    - Spring Security 설정에서 `.csrf()` 메서드를 통해 CSRF 보호를 활성화하거나 비활성화할 수 있으며, REST API 환경에 맞게 조정이 가능합니다.

이와 같이 CSRF 보호는 스프링 시큐리티의 핵심 보안 메커니즘 중 하나로, 내부 필터(`CsrfFilter`)를 통해 토큰 기반의 검증 과정을 거쳐 애플리케이션의 보안을 강화합니다.
  
### 예제
```java
@Configuration
public class CsrfSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests(auth -> auth
                        .requestMatchers("csrf").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
        ;

        return http.build();
    }
}
```

```http request
### CSRF
POST http://localhost:8080/csrf
Content-Type: application/json
```
이런식으로 요청을 하게되면 스프링에서 특정 html파일을 응답해 주는데 여기 `form`테크를 확인해보면 hidden으로 _csrf 토큰값을 전달해 주는 것을 확인할 수 있다. 
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet"
          integrity="sha384-oOE/3m0LUMPub4kaC09mrdEhIc+e3exm4xOGxAmuFXhBNF4hcg/6MiAXAf5p0P56" crossorigin="anonymous"/>
</head>
<body>
<div class="container">
    <form class="form-signin" method="post" action="/login">
        <h2 class="form-signin-heading">Please sign in</h2>
        <p>
            <label for="username" class="sr-only">Username</label>
            <input type="text" id="username" name="username" class="form-control" placeholder="Username" required
                   autofocus>
        </p>
        <p>
            <label for="password" class="sr-only">Password</label>
            <input type="password" id="password" name="password" class="form-control" placeholder="Password" required>
        </p>
        <input name="_csrf" type="hidden"
               value=BrRIJn-BMmXg25bdXXYoQ8oVyfapywy4OFz9pxFYXKx-tKcOMNYrFh3kBVLNuqTrP1scJ65x5M7L-zmVCWrKlyFhb55KjcZo/>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
    </form>
</div>
</body>
</html>
```

해당 토큰값을 포함해서 동일한 URL로 호출하게 되면 성공하게 되는 것을 확인할 수 있다.
```http request
### CSRF with token
POST http://localhost:8080/csrf
Content-Type: application/x-www-form-urlencoded

_csrf = BrRIJn-BMmXg25bdXXYoQ8oVyfapywy4OFz9pxFYXKx-tKcOMNYrFh3kBVLNuqTrP1scJ65x5M7L-zmVCWrKlyFhb55KjcZo
```


### CSRF 토큰 유지 - CsrfTokenRepository

- .CsrfToken 은 CsrfTokenRepository를 사용하여 영속화 하며 HttpSessionCsrfTokenRepository와 CookieCsrfTokenRepository 를 지원한다.
- 두 군데 중 원하는 위치에 토큰을 저장하도록 설정을 통해 지정할 수 있다.

### 1. `HttpSessionCsrfTokenRepository`

- CSRF 토큰을 **서버 세션(HttpSession)** 에 저장
- 클라이언트에는 토큰을 전달하지 않으며, JavaScript로 직접 접근할 수 없음
- `HttpSessionCsrfTokenRepository` 는 기본적으로 HTTP 요청 헤더인 `X-CSRF-TOKEN`  또는 요청 매개변수인 _csrf 토큰을 읽는다.
- 기본

```java

http
  .csrf(csrf -> csrf
    .csrfTokenRepository(new HttpSessionCsrfTokenRepository())
  );

```

### 2. `CookieCsrfTokenRepository`

- CSRF 토큰을 **쿠키에 저장하여 클라이언트로 전달**
- JavaScript에서 CSRF 토큰을 **읽어서 헤더에 넣는 구조**에 적합
- 기본적으로 `CXSRF-TOKEN` 며을 가진 쿠키에 저장하고 HTTP 요청 헤더 `X-XSRF-TOEKN` 또는 매개변수인 _csrf에서 읽는다.
- REST API, SPA(프론트-백엔드 분리) 환경에서 자주 사용

```java

http
  .csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
  );

```

> withHttpOnlyFalse() 설정은 JavaScript에서 쿠키에 접근 가능하도록 허용
>
>
> 즉, JS가 이 토큰을 읽어 요청 헤더에 넣을 수 있도록 함
>

---

### 🛠️ 커스터마이징 가능한 점

- 쿠키 이름, 경로, 도메인 등을 지정 가능 (`CookieCsrfTokenRepository`)
- 헤더명, 파라미터명 지정 가능 (`HttpSessionCsrfTokenRepository`)

예시:

```java

CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();
repo.setCookieName("XSRF-TOKEN");
repo.setHeaderName("X-XSRF-TOKEN");

http.csrf(csrf -> csrf
  .csrfTokenRepository(repo)
);

```

---

### 최종 정리

| 항목 | 설명 |
| --- | --- |
| **역할** | CSRF 토큰을 생성하고 클라이언트와 서버 간 상태를 유지 |
| **저장 위치** | `HttpSession` 또는 `Cookie` 중 선택 |
| **SPA 또는 REST API 환경** | `CookieCsrfTokenRepository` 선호 |
| **서버 렌더링 앱** | `HttpSessionCsrfTokenRepository` 사용이 일반적 |

---

### CSRF 토큰 처리 - CsrfToeknRequestHandler

Spring Security는 요청과 응답 과정에서 CSRF 토큰을 처리하는 방법을 정의하는 인터페이스로 `CsrfTokenRequestHandler`를 제공합니다.

---

### **CsrfTokenRequestHandler란?**

`CsrfTokenRequestHandler`는 Spring Security가 제공하는 인터페이스로,

각 요청(request)과 응답(response)의 흐름에서 **CSRF 토큰을 어떻게 처리할지 정의**합니다.

주로 다음 역할을 수행합니다.

- **CSRF 토큰 생성 및 조회**
- 클라이언트에 전달되는 응답에 **토큰 추가**
- 요청과 응답 간에 **토큰의 상태 유지**

---

### **주요 구현체**

기본적으로 제공되는 주요 구현체는 다음과 같습니다.

| 구현체 | 역할 및 특징 |
| --- | --- |
| `XorCsrfTokenRequestAttributeHandler` | 요청 속성(request attribute)에 CSRF 토큰을 저장하고 클라이언트에 전달. <br/> SPA와 같은 JavaScript 기반 애플리케이션에서 많이 사용 |
| `CsrfTokenRequestAttributeHandler` | 기본 구현으로, 토큰을 요청 속성에 담아 뷰(View)로 전달 |

최근 **Spring Security 6.x** 버전부터는 `XorCsrfTokenRequestAttributeHandler`가 기본으로 사용됩니다.
  
```java 
   DeferredCsrfToken deferredCsrfToken = this.tokenRepository.loadDeferredToken(request, response);
        request.setAttribute(DeferredCsrfToken.class.getName(), deferredCsrfToken);
CsrfTokenRequestHandler var10000 = this.requestHandler; // 기본 handler XorCsrfTokenRequestAttributeHandler
        Objects.requireNonNull(deferredCsrfToken);
        var10000.handle(request, response, deferredCsrfToken::get);
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
        if (this.logger.isTraceEnabled()) {
        this.logger.trace("Did not protect against CSRF since request did not match " + this.requireCsrfProtectionMatcher);
            }

                    filterChain.doFilter(request, response);
        }

```
  
```java
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> deferredCsrfToken) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        Assert.notNull(deferredCsrfToken, "deferredCsrfToken cannot be null");
        Supplier<CsrfToken> updatedCsrfToken = this.deferCsrfTokenUpdate(deferredCsrfToken); // 받아온 토큰을 다시하번더 Supplier로 감싸고있다.
        super.handle(request, response, updatedCsrfToken); // 부모 클레스인 CsrfTokenRequestAttributeHandler의 handle을 호출
    }
    
private Supplier<CsrfToken> deferCsrfTokenUpdate(Supplier<CsrfToken> csrfTokenSupplier) {
    return new CachedCsrfTokenSupplier(() -> {
        CsrfToken csrfToken = (CsrfToken)csrfTokenSupplier.get();
        Assert.state(csrfToken != null, "csrfToken supplier returned null");
        String updatedToken = createXoredCsrfToken(this.secureRandom, csrfToken.getToken());
        return new DefaultCsrfToken(csrfToken.getHeaderName(), csrfToken.getParameterName(), updatedToken);
    });
}    
    
```
  
코드를 확인해보면 CsrfToken을 지속적으로 Supplier 객체로 감싸서 처리하는 것을 확인할 수 있는데 이는 최대한 실행시점을 지연 시켜서 성능상 이점을 얻기 위함이다.

  
`super.handle(CsrfTokenRequestAttributeHandler의)`  
```java
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> deferredCsrfToken) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        Assert.notNull(deferredCsrfToken, "deferredCsrfToken cannot be null");
        request.setAttribute(HttpServletResponse.class.getName(), response);
        CsrfToken csrfToken = new SupplierCsrfToken(deferredCsrfToken);
        request.setAttribute(CsrfToken.class.getName(), csrfToken); // 토큰을 request 객체에 저장
        String csrfAttrName = this.csrfRequestAttributeName != null ? this.csrfRequestAttributeName : csrfToken.getParameterName();
        request.setAttribute(csrfAttrName, csrfToken);
    }

```
  
전달받은 `CsrfToken`을 `request` 객체에 저장하고있다. 그렇다면 request 객체에 `csrf`클레스 으림으로 토큰을 저장하는 이유는 무엇일까??  

우리가 이전에 CSRF이 없는 경우 자동으로 SpringSecurity에서 hidden 속성으로 `_csrf`이름의 input 태그를 자동적으로 생성한 것을 확인할 수 있었는데 이를 생성할때 사용하기 위해서 request 객체에 저장하는 것이다.
  
그렇기 때문에 이 토큰 값을 스프링 MVC 에서 받아서 별도의 처리 또한 가능하다.  
  
이렇게 매 요청마다 실행되도 실제 Supplier 객체로 감싸기 때문에 
```java
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
     
        } else {
CsrfToken csrfToken = deferredCsrfToken.get(); // 실제 동작하는 구문
String actualToken = this.requestHandler.resolveCsrfTokenValue(request, csrfToken);
            if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
boolean missingToken = deferredCsrfToken.isGenerated();
                this.logger.debug(LogMessage.of(() -> "Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request)));
AccessDeniedException exception = (AccessDeniedException)(!missingToken ? new InvalidCsrfTokenException(csrfToken, actualToken) : new MissingCsrfTokenException(actualToken));
                this.accessDeniedHandler.handle(request, response, exception);
            } else {
                    filterChain.doFilter(request, response);
            }
                    }
                    }

```  
  
실제 데이터를 조작하는 http 요청인 경우에만 동작하게 된다.
그래서 실제 동작 과정에서  
```java
CsrfToken csrfToken = deferredCsrfToken.get(); // 실제 동작하는 구문
String actualToken = this.requestHandler.resolveCsrfTokenValue(request, csrfToken);

```
서버에 저장되어 있는 csrfToken과 사용자가 전달한 토큰 값(actualToken)을 비교해서 처리하게 된다.  
토큰이 일치하지 않으면 기본적으올 403 에러와 함께 마치 권한이 없는 것처럼 응답을 클라이언트에게 전달하게된다.(this.accessDeniedHandler.handle(request, response, exception))


---

### **대표적인 처리 흐름**

다음은 대표적인 CSRF 토큰 처리 흐름입니다.

1. 요청(request)이 들어오면 **기존 CSRF 토큰 존재 여부**를 확인
    1. _csrf 및 CsrfToken.clas.getName() 명으로 HttpServletRequest 속성에 CsrfToken 을 저장하며 HttpServletRequest으로부터 CsrfToken을 꺼내어 참조 할 수 있다.
    2. 토큰 값은 요청 헤더(기본적으로 X-CSRF-TOKEN 또는 X-XSRF-TOKEN 중하나) 또는 요청 메개변수 (_csrf) 중 하나로부터 토큰의 유효성 비교 및 검증을 해
    3. 클라이언트의 매 요청마다 CSRF 토큰 값(UUID)에 난수를 인코딩하여 변경한 CsrfToken이 반환 되도록 보장한다. 세션에 저장된 원본 토큰 값은 그대로 유지된다.
    4. 헤더 값 또는 요청 매개변수로 전달된 인코딩 된 토큰은 원본 토큰을 얻기 위해 디코딩되며, 그런 다음 세션 혹은 쿠키에 저장된 영구적인 CsrfToken 과 비교된다.
2. 토큰이 없으면 새로 **토큰 생성**
3. 요청(request)의 속성(attribute)에 CSRF 토큰을 저장하여 컨트롤러나 뷰에 전달
4. 응답(response)에 CSRF 토큰을 추가하여 클라이언트가 이를 전달받을 수 있게 함

---

### **사용 예시 (Spring Security 6.x 이상)**


```java
public final class CookieCsrfTokenRepository implements CsrfTokenRepository {
    static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN"; // 기본 쿠키명
}
```
![img_23.png](../../img/img_23.png)  
  
위의 쿠키는 HttpOnly 에 체크되어 있는데 이는 http 통신시에만 사용할 수 있다. 만약에 쿠키를 javascript 에서 사용하고 싶다면 withHttpOnlyFalse 옵션을 사용하면 된다.

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler())
        );

    return http.build();
}

```
![img_24.png](../../img/img_24.png)  

- 위의 예제는 **쿠키 기반의 토큰 저장** 및 **XOR 기반의 요청 속성 처리를 사용한 예**입니다.

---

### **XorCsrfTokenRequestAttributeHandler 특징**

- 토큰을 **XOR 연산으로 인코딩**하여 클라이언트로 전달
- JavaScript 기반 앱(React, Vue 등)과 함께 사용 시 편리함
- 보안성을 높이면서도 토큰 관리가 용이함

---

### **어떤 경우에 사용해야 하는가?**

| 상황 | 권장 사용 방식 |
| --- | --- |
| 서버 사이드 렌더링 (JSP, Thymeleaf) | 기본 제공되는 `CsrfTokenRequestAttributeHandler` 사용 |
| SPA 및 REST API 기반 | `XorCsrfTokenRequestAttributeHandler` + `CookieCsrfTokenRepository` |

---

### **최종 정리**

| 항목 | 설명 |
| --- | --- |
| **역할** | 요청·응답 간 CSRF 토큰 처리 및 전달 |
| **주요 구현체** | `CsrfTokenRequestAttributeHandler`(기본), <br/> `XorCsrfTokenRequestAttributeHandler` |
| **기본 값(Spring Security 6.x~)** | `XorCsrfTokenRequestAttributeHandler` (권장) |
| **추천 조합(SPA)** | Cookie + XOR Handler 조합 |

---

## **CSRF 토큰 지연 로딩 (Deferred CSRF Token Loading)**

Spring Security에서는 성능 최적화를 위해 **CSRF 토큰의 생성을 지연**하는 방식(Deferred Loading)을 제공합니다.

즉, 요청이 들어올 때 무조건 CSRF 토큰을 생성하지 않고,

실제로 필요할 때만 토큰을 생성하는 방법입니다.

---

## 📌 **지연 로딩의 배경**

기본적으로 Spring Security는 모든 요청에 CSRF 토큰을 즉시 생성합니다. 그러나:

- 정적 리소스 요청 (CSS, JS, 이미지) 등에서는 CSRF 토큰이 필요하지 않음
- API나 특정 엔드포인트에 CSRF 보호가 불필요한 경우가 존재함

이러한 상황에서는 **매 요청마다 토큰을 생성하는 것 자체가 불필요한 자원 소모**가 됩니다.

이 문제를 해결하기 위해 Spring Security는 **CSRF 토큰 지연 로딩**을 지원합니다.

---

## 🎯 **지연 로딩의 동작 원리**

CSRF 토큰의 지연 로딩은 다음과 같은 원리로 작동합니다.

- 요청(request)이 처음 도착했을 때 **CSRF 토큰을 즉시 생성하지 않음**
- 실제로 **토큰이 필요한 시점(뷰에서 토큰 호출 또는 API에서 CSRF 토큰 접근)**에 비로소 생성
- 생성된 토큰은 이후 필요한 요청에 재사용

이로 인해 초기 요청에서 **불필요한 부하가 감소**하고 성능이 개선됩니다.
  
```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        DeferredCsrfToken deferredCsrfToken = this.tokenRepository.loadDeferredToken(request, response);
        request.setAttribute(DeferredCsrfToken.class.getName(), deferredCsrfToken);
        CsrfTokenRequestHandler var10000 = this.requestHandler;
        Objects.requireNonNull(deferredCsrfToken);
        var10000.handle(request, response, deferredCsrfToken::get); // 실제 토큰을 사용 시점에서 생성한다.
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Did not protect against CSRF since request did not match " + this.requireCsrfProtectionMatcher);
            }

            filterChain.doFilter(request, response);
        } else {
            CsrfToken csrfToken = deferredCsrfToken.get(); // 실제 토큰을 사용 시점에서 생성한다.
            String actualToken = this.requestHandler.resolveCsrfTokenValue(request, csrfToken);
            if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
                boolean missingToken = deferredCsrfToken.isGenerated();
                this.logger.debug(LogMessage.of(() -> "Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request)));
                AccessDeniedException exception = (AccessDeniedException)(!missingToken ? new InvalidCsrfTokenException(csrfToken, actualToken) : new MissingCsrfTokenException(actualToken));
                this.accessDeniedHandler.handle(request, response, exception);
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }



```  
  
```java
final class RepositoryDeferredCsrfToken implements DeferredCsrfToken {
    private final CsrfTokenRepository csrfTokenRepository;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private CsrfToken csrfToken;
    private boolean missingToken;

    RepositoryDeferredCsrfToken(CsrfTokenRepository csrfTokenRepository, HttpServletRequest request, HttpServletResponse response) {
        this.csrfTokenRepository = csrfTokenRepository;
        this.request = request;
        this.response = response;
    }

    public CsrfToken get() {
        this.init(); // 사용 시점에 생성한다.
        return this.csrfToken;
    }

    public boolean isGenerated() {
        this.init();
        return this.missingToken;
    }

    private void init() {
        if (this.csrfToken == null) {
            this.csrfToken = this.csrfTokenRepository.loadToken(this.request);
            this.missingToken = this.csrfToken == null;
            if (this.missingToken) {
                this.csrfToken = this.csrfTokenRepository.generateToken(this.request);
                this.csrfTokenRepository.saveToken(this.csrfToken, this.request, this.response);
            }

        }
    }
}


```

만약 지연 로딩을 사용하지 않는 경우 에는  
```java
        XorCsrfTokenRequestAttributeHandler defaultHandler = new XorCsrfTokenRequestAttributeHandler();
        defaultHandler.setCsrfRequestAttributeName(null); //지연 로딩 사용X
```
이렇게 설정하게 되면  
  
```java
public class CsrfTokenRequestAttributeHandler implements CsrfTokenRequestHandler {
    private String csrfRequestAttributeName = "_csrf";

    public CsrfTokenRequestAttributeHandler() {
    }

    public final void setCsrfRequestAttributeName(String csrfRequestAttributeName) {
        this.csrfRequestAttributeName = csrfRequestAttributeName;
    }

    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> deferredCsrfToken) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        Assert.notNull(deferredCsrfToken, "deferredCsrfToken cannot be null");
        request.setAttribute(HttpServletResponse.class.getName(), response);
        CsrfToken csrfToken = new SupplierCsrfToken(deferredCsrfToken);
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        String csrfAttrName = this.csrfRequestAttributeName != null ? this.csrfRequestAttributeName : csrfToken.getParameterName(); // 해당 부분에서 바로 토큰값을 반환 -> Supplier를 바로 실해시킴
        request.setAttribute(csrfAttrName, csrfToken);
    }
}

```


---


## ⚙️ **Spring Security에서의 설정 방법**

### ✅ 기본 설정 (Spring Security 6.x 이상)

기본적으로 **Spring Security 6.x 버전부터는 지연 로딩이 활성화**되어 있습니다.

하지만 명시적으로 설정할 때는 다음과 같이 사용합니다.

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(new CookieCsrfTokenRepository())
            .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()::handle)
        );

    return http.build();
}

```

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

XorCsrfTokenRequestAttributeHandler handler = new XorCsrfTokenRequestAttributeHandler();
handler.setCsrfRequestAttributeName(null); //지연된 토큰을 사용하지 않고 CsrfToken을 모든 요청마다 로드한다.
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(new CookieCsrfTokenRepository())
            .csrfTokenRequestHandler(handler)
        );

    return http.build();
}
```

- 위 예시의 설정은 **기본적으로 Deferred 방식(지연 로딩)을 내장**하고 있습니다.

### 명시적으로 지연 로딩하기 위한 방법 (더 구체적인 예제)

명확히 지연 로딩을 보장하고자 할 때는 다음과 같은 설정도 가능합니다.

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();

    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(new LazyCsrfTokenRepository(csrfTokenRepository)) // 지연 로딩 활성화
            .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler())
        );

    return http.build();
}

```

여기서 사용하는 `LazyCsrfTokenRepository`는 실제로 지연 로딩을 명시적으로 지원하는 Spring Security에서 제공하는 구현체로, 내부적으로 필요 시점에 실제 토큰을 생성하는 역할을 합니다.

---

## 📝 **LazyCsrfTokenRepository 내부 구현**

`LazyCsrfTokenRepository`의 주요 로직을 요약하면 다음과 같습니다.

```java

public final class LazyCsrfTokenRepository implements CsrfTokenRepository {

	private final CsrfTokenRepository delegate;

	public LazyCsrfTokenRepository(CsrfTokenRepository delegate) {
		this.delegate = delegate;
	}

	@Override
	public CsrfToken generateToken(HttpServletRequest request) {
		return delegate.generateToken(request);
	}

	@Override
	public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
		if (token == null && loadToken(request) == null) {
			return; // 필요 없으면 저장하지 않음
		}
		delegate.saveToken(token, request, response);
	}

	@Override
	public CsrfToken loadToken(HttpServletRequest request) {
		return delegate.loadToken(request);
	}
}

```

- **요청 시점에 로드 요청이 발생할 때만 실제 delegate가 토큰을 생성하고 저장**합니다.
- 불필요한 호출 및 성능 낭비를 방지합니다.
  
  
---

### CSRF 통합

CSRF 공격을 방지하기 위한 토큰 패턴을 사용하려면 CSRF 토큰을 HTTP 요청에 포함해야한다. 그래서 브라우저에 의해 HTTP 요청에 자동으로 포함되지 않는 요청 부분(폼, HTTP 헤더 또는 기타 부분) 중 하나중에 포함 되어야한다.

클라이언트 어플리케이션이 CSRF로 보호된 백엔드 어플리케이션과 통합하는 여러가지 방법을 살표보자

### HTML Forms

HTML 폼을 서버에 제출하려면 CRSF 토큰을 hidden 값으로 Form에 포함해야한다.

```html
<form action="/toekn" method="post">
	 <!-- CSRF 토큰을 자동으로 추가 -->
    <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
</form >
```

### JavaScript Application

### SPA

### 서버 측 과정

1. **초기 로드 시 CSRF 토큰 제공**
    - SPA의 경우, 서버는 초기 HTML 응답이나 별도의 API 엔드포인트를 통해 CSRF 토큰을 제공할 수 있습니다.
    - 예를 들어, HTML 헤더에 메타 태그로 CSRF 토큰과 헤더 이름을 포함할 수 있습니다:

        ```html
        
        <meta name="_csrf" content="${_csrf.token}" />
        <meta name="_csrf_header" content="${_csrf.headerName}" />
        
        ```

    - 또는 JSON 형태의 API 응답으로 CSRF 토큰을 전달할 수도 있습니다.
2. **토큰 저장 및 관리**
    - 클라이언트 측 자바스크립트는 페이지 로드 시 또는 API 호출로 전달받은 CSRF 토큰을 전역 변수나 상태 관리 라이브러리(Redux, Context API 등)에 저장합니다.
    - SPA는 한 번 로드된 후 페이지 이동 없이 동적으로 데이터 요청을 수행하기 때문에, 저장된 토큰을 계속 사용합니다.
    - 만약 세션이나 토큰 만료에 대비하여 토큰 갱신 API가 존재한다면, 주기적으로 토큰을 업데이트합니다.

### 클라이언트 측 과정

1. **AJAX/API 요청 시 CSRF 토큰 포함**
    - SPA에서 모든 API 요청(POST, PUT, DELETE 등 상태 변경 요청) 시, 저장된 CSRF 토큰을 요청 헤더나 파라미터에 첨부합니다.
    - 예를 들어, `fetch` API를 사용하는 경우:

        ```jsx
        
        const csrfToken = /* 초기 로드 시 저장된 토큰 */;
        const csrfHeader = /* 초기 로드 시 저장된 헤더 이름 */;
        
        fetch('/api/endpoint', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                [csrfHeader]: csrfToken
            },
            body: JSON.stringify({ key: 'value' })
        });
        
        ```

2. **토큰 갱신(선택적)**
    - 장시간 사용되는 SPA의 경우, 세션 만료나 CSRF 토큰의 유효기간이 지나면, 별도의 토큰 갱신 API를 호출하여 새로운 토큰으로 업데이트할 수 있습니다.
3. **보안 강화**
    - 일부 프레임워크(예: Angular)는 HTTP 인터셉터를 통해 모든 요청에 자동으로 CSRF 토큰을 첨부하도록 지원합니다.
    - 이렇게 하면 개발자가 매번 토큰을 수동으로 추가할 필요 없이, 자동으로 헤더에 포함됩니다.

### 서버 측 검증 (공통)

- 서버는 API 요청에서 헤더나 파라미터로 전달된 CSRF 토큰을 읽고, 세션이나 저장소에 있는 토큰과 비교합니다.
- 토큰이 유효하면 요청을 처리하고, 그렇지 않으면 CSRF 공격으로 간주하여 접근을 차단합니다.

### 전통적인 다중 페이지 애플리케이션

### 서버 측 과정

1. **페이지 요청 시 CSRF 토큰 생성 및 저장**
    - 사용자가 브라우저로 페이지를 요청하면, 서버(예: Spring Security)는 해당 요청에 대해 CSRF 토큰을 생성합니다.
    - 이 토큰은 세션이나 지정된 저장소(예: `CsrfTokenRepository`)에 저장되고, 동시에 모델에 `_csrf`라는 이름으로 추가됩니다.
2. **HTML 렌더링 시 CSRF 토큰 포함**
    - 템플릿 엔진(예: Thymeleaf, JSP 등)을 사용하여 페이지를 렌더링할 때, CSRF 토큰을 `<input type="hidden">` 필드에 삽입합니다.
    - 예를 들어, Thymeleaf에서는 다음과 같이 토큰이 자동으로 전달됩니다:

        ```html
        
        <form th:action="@{/submit}" method="post">
            <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
            <!-- 나머지 폼 필드 -->
            <button type="submit">제출</button>
        </form>
        
        ```

3. **요청 처리 시 토큰 검증**
    - 사용자가 폼을 제출하면, CSRF 토큰도 함께 전송됩니다.
    - 서버는 세션 또는 저장소에 있는 CSRF 토큰과 클라이언트로부터 전달받은 토큰을 비교합니다.
    - 토큰이 일치하면 요청을 허용하고, 일치하지 않으면 CSRF 공격으로 간주하여 요청을 거부합니다.

### 클라이언트 측 과정

- **폼 제출**
    - 사용자는 웹 페이지의 폼에 데이터를 입력하고 제출합니다.
    - 폼 내 숨겨진 필드에 포함된 CSRF 토큰도 함께 전송되어, 서버에서 검증에 사용됩니다.
- **AJAX 요청(선택적)**
    - 만약 일부 요청이 AJAX로 처리된다면, 서버가 HTML 메타 태그나 자바스크립트 변수로 CSRF 토큰을 노출하고,

        ```html
        
        <meta name="_csrf" content="${_csrf.token}" />
        <meta name="_csrf_header" content="${_csrf.headerName}" />
        
        ```

    - 자바스크립트 코드가 이 토큰을 읽어 모든 AJAX 요청 헤더에 추가합니다.

        ```jsx
        
        $(document).ajaxSend(function(event, xhr) {
            var token = $('meta[name="_csrf"]').attr('content');
            var header = $('meta[name="_csrf_header"]').attr('content');
            xhr.setRequestHeader(header, token);
        });
        
        ```


---

## 최종 정리

### 전통적 다중 페이지 애플리케이션 (Non-SPA)

- **서버 측**: 페이지 렌더링 시 CSRF 토큰을 모델에 포함 → HTML 폼 내 숨겨진 필드로 전달 → 요청 제출 시 토큰 검증.
- **클라이언트 측**: 폼 제출 시 자동으로 토큰이 전송되며, 선택적으로 AJAX 요청 시 메타 태그로 노출된 토큰을 헤더에 추가.

### 단일 페이지 애플리케이션 (SPA)

- **서버 측**: 초기 로드 시 HTML 메타 태그나 API 응답으로 CSRF 토큰을 제공.
- **클라이언트 측**: 자바스크립트가 토큰을 저장한 후, 모든 AJAX/API 요청 시 토큰을 요청 헤더(또는 파라미터)에 포함 → 필요한 경우 토큰 갱신 로직 구현.
- **공통**: 서버는 요청에 포함된 CSRF 토큰을 세션 또는 저장소에 있는 토큰과 비교하여 검증.

이와 같이, 각각의 방식은 애플리케이션의 구조에 따라 CSRF 토큰을 관리하고 검증하는 절차와 구현 방식이 다르며, 서버와 클라이언트 양측에서 올바른 처리 과정을 구현해야 CSRF 공격을 효과적으로 방