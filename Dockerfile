# Build stage: compile the app with the Maven wrapper
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY mvnw pom.xml ./
COPY .mvn .mvn
# Download dependencies first, so this layer is cached when only the code changes
RUN ./mvnw -q dependency:go-offline
COPY src src
# Tests need Docker (Testcontainers), so they run with ./mvnw test outside the image build
RUN ./mvnw -q package -DskipTests

# Run stage: only the Java runtime and the jar
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/mini-wsa-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
