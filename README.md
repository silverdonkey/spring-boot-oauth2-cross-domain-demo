## Spring Security Cross-Domain Auth utilizing OAuth2 TokenExchange Flow

How-To Start the Keycloack Server (it's a Keycloak with preconfigured Baeldung Realm): 

    cd keycloak
    docker compose -f compose.yml up -d

* [Keycloak Admin Console](http://localhost:8080/auth)
  * admin/admin
* [Keycloak OIDC Config](http://localhost:8080/auth/realms/baeldung/.well-known/openid-configuration)
* To get an access_token from Keycloak: configure OAuth2 authentication with Postman
  * user/user
* [Postman-Collection](Cross-Domain-IAM-with-Spring-AuthZ-Server.postman_collection.json)
* Use [jwt.io](https://jwt.io) to decode the generated tokens

How-To Start the Custom Spring AuthZ Server:

    cd spring-authorization-server
    ./gradlew bootRun

Generate customized access_token with client_credentials flow: 

    curl -u service-client-1:service-secret -X POST \
    -d "grant_type=client_credentials" \
    http://localhost:9000/oauth2/token

Generate customized access_token using an external access_token (from Keycloak) and utilizing TokenExchange flow:

    curl -u exchange-client-1:exchange-secret -X POST \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=EXTERNAL_ACCESS_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    http://localhost:9000/oauth2/token

* [Custom Spring Authorization Server Config](http://localhost:9000/.well-known/oauth-authorization-server)
