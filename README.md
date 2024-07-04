# Spring security
## 환경 설정
- jdk 17 이상
- Gradle
- postgresql

### Docker postgresql 설정
 - 도커 이미지 설치
```sh
docker pull postgres:latest
```
- 이미지 확인 
```sh
docker images
```

- 컨테이너 생성 
```sh
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD="test1234" --name security-postgre postgres
```

- 컨테이너 진입
```sh
docker exec --user="root" -it security-postgre "bash"
```

- postgresql 명령어
```sh
psql -U postgres
```

- 계정 생성
```sh
CREATE USER pgadm WITH PASSWORD 'test1234';
```
- 역할 추가
```sh
ALTER ROLE pgadm CREATEDB Superuser;
```
- 스키마 생성
```sh
create database springsecurity;
```

- 스키마 접근(생성 확인)
```sh
\c springsecurity
```

