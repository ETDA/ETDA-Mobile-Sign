#
# Build stage
#
FROM maven:3.8.1-openjdk-15-slim AS build
COPY ./src /home/app/src
COPY ./pom.xml /home/app
RUN mvn -f /home/app/pom.xml clean package

#
# Package stage
#
FROM openjdk:15.0.2-jdk-oracle
RUN mkdir /var/config
RUN microdnf update -y && microdnf install -y git cronie
COPY --from=build /home/app/target/XmlSignerAPI-0.0.1.jar /opt/XmlSigner/XmlSignerAPI.jar
COPY ./src/test/resources/conf /var/config/XmlSigner

ENV TZ="Asia/Bangkok"

# Run the JAR file
CMD ["java","-Dserver.port=8090","-jar","/opt/XmlSigner/XmlSignerAPI.jar"]