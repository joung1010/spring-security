FROM amazoncorretto:21-alpine-jdk

RUN apk update && \
    apk add freetype fontconfig ttf-dejavu

WORKDIR /app

COPY build/libs/app.jar /app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app.jar"]

