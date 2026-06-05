FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /secureauth
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests clean package

FROM eclipse-temurin:21-jre
WORKDIR /secureauth
RUN useradd -r -u 1001 authuser
COPY --from=build /secureauth/target/*.jar secureauth.jar

EXPOSE 8080
USER authuser
ENTRYPOINT ["java", "-jar", "/secureauth/secureauth.jar"]

