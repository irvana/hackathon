FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:17-jre
RUN apt-get update && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /build/target/ops-simulator-1.0.0-SNAPSHOT.jar ops-simulator.jar
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENV AUTH_SERVICE_BASE_URL=http://auth-service:8080 \
    WEBHOOK_URL=http://webhook-mock:9000/webhook

ENTRYPOINT ["/app/docker-entrypoint.sh"]
