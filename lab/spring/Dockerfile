# Vulnerable Spring lab for CVE-2026-114938.
#
# The JDK is pinned to 21.0.13+9 — the last vulnerable build (fixed in 21.0.13.1).
# Build and run in one stage so the app runs on the vulnerable runtime.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package

FROM eclipse-temurin:21.0.13_9-jdk
WORKDIR /app
COPY --from=build /src/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-XX:+UseG1GC", "-jar", "/app/app.jar"]
