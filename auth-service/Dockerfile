FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:17-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /build/target/auth-service-1.0.0-SNAPSHOT.jar app.jar
COPY --from=build /build/target/dd-java-agent.jar dd-java-agent.jar
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENV DD_AGENT_HOST=datadog-agent \
    DD_ENV=hackathon \
    DD_SERVICE=auth-service \
    DD_AGENT_METRICS_ENABLED=true

HEALTHCHECK --interval=5s --timeout=5s --retries=15 --start-period=40s \
  CMD curl -sf http://localhost:8080/actuator/health || exit 1

EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
