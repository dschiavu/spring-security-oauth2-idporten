# Spring Boot OAuth2 Authorization Code Flow Demo using [ID-porten](https://samarbeid.difi.no/felleslosninger/id-porten)

## About

### This Demo

This example is based on the 
[Spring Boot OAuth2 Tutorial](https://spring.io/guides/tutorials/spring-boot-oauth2/#_social_login_authserver).

It uses Spring Security OAuth2 support (`spring-security-oauth2`) 
to to enable ID-porten Single Sign-On (SSO) in the Spring Boot web application 
using 
[ID-porten's OAuth2 Authorization Code Flow](https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_codeflow.html).

Before running the demo, you need to enter your ID-porten credentials in  
[application.yml](./src/main/resources/application.yml), the `client ID` 
and the `client secret`.

#### ID-porten

[ID-porten](https://samarbeid.difi.no/felleslosninger/id-porten) is a Norwegian 
nationwide cross-domain federated SSO authentication mechanism used for 
authenticating users in Norway, supporting OAuth2, OpenID 1, SAML and other 
protocols.

#### Note

Use this demo as-is and at your own risk. No guarantees are provided. This is 
not an official project nor affiliated in any way with ID-porten.

### Implementation

This demo uses a static client secret authentication (ie. HTTP Basic 
Authentication) to obtain the authentication code, although JWK authentication 
could be easily supported as well.

We secure the app by using a fairly standard Spring Web Security configuration, 
creating a session for the user after performing the ID-porten authentication. 
`spring-security-oauth2` does most of the work here.

A custom `IdPortenClientAuthenticationProcessingFilter` stores the `id_token`
for later use as we need it to call the OpenID `/endsession` endpoint on logout.
The logout process is handled by the `IdPortenOidcEndpointLogoutHandler`, a 
`LogoutSuccessHandler` which invokes the OID `/endsession` endpoint providing
the `id_token_hint` value stored previously in the session.

We also retrieve the logged in user's unique National Identity Number (which is 
stored as the `pid` claim returned by the OID `/userinfo` endpoint), and we 
store it as the user's `Principal`. 

### See Also

* [ID-porten Architecture](https://difi.github.io/idporten-oidc-dokumentasjon/oidc_arch.html)
* [ID-porten OAuth2 Auth Code Flow Specification](https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_codeflow.html)
