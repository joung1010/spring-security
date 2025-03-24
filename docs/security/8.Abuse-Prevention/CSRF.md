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
java
복사
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

