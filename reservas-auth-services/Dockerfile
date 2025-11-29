# ETAPA 1: Construcción (Builder)
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

# Copiamos solo los archivos necesarios para descargar dependencias
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

# Damos permisos de ejecución al wrapper y descargamos dependencias
RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline

# Copiamos el código fuente y los recursos
COPY src ./src

# Compilamos y empaquetamos
RUN ./mvnw package -DskipTests

# Extraemos el nombre del jar generado para usarlo en la siguiente etapa
RUN cp target/*.jar app.jar

# ETAPA 2: Ejecución (Runtime)
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Creamos un usuario sin privilegios por seguridad
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copiamos el JAR desde la etapa de construcción
COPY --from=builder /app/app.jar app.jar

# Copiamos el keystore.jks necesario para OAuth2
COPY --from=builder /app/src/main/resources/keystore.jks keystore.jks

# Exponemos el puerto 8081
EXPOSE 8081

# Comando de inicio
ENTRYPOINT ["java", "-jar", "app.jar"]