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