FROM eclipse-temurin:21-jre-jammy

RUN apt-get update \
    && apt-get install --no-install-recommends -y age \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target/integrant-service-standalone.jar /app/app.jar

ENV SERVICE_ENV=prod
EXPOSE 8080
# Inject the raw age identity at runtime; never bake a private key into an image.
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
