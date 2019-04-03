package com.example.demo.auth;

import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;

import java.util.Map;

/**
 * Extract's the user's NiN into the Principal object
 * <p>
 * The {@code pid} claim in ID-porten corresponds to the user's unique Norwegian National Identity Number
 *
 * @see <a href="https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_codeflow.html#idtoken">
 * ID-porten OAuth2/OpenID Auth Code Flow, Structure of the ID Token</a>
 */
public class IdPortenPrincipalExtractor implements PrincipalExtractor {

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        return map.get("pid");
    }
}
