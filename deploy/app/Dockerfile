# 1) Build stage
FROM eclipse-temurin:17-jdk AS builder
WORKDIR /app

# 먼저 의존성 캐시(빌드 빨라짐)
COPY pom.xml ./
COPY .mvn .mvn
COPY mvnw ./
RUN chmod +x mvnw
RUN ./mvnw -q -DskipTests dependency:go-offline

# 소스 복사 후 패키징
COPY src src
RUN ./mvnw -DskipTests package

# 2) Run stage
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
