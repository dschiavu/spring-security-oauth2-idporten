package com.example.demo.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * A custom filter, mostly identical to {@link OAuth2ClientAuthenticationProcessingFilter} other than it preserves the
 * id_token for later usage, primarily to be able to invoke ID-porten's {@code /endsession} endpoint with the
 * {@code id_token_hint} parameter on logout.
 */
public class IdPortenClientAuthenticationProcessingFilter extends OAuth2ClientAuthenticationProcessingFilter {

    public IdPortenClientAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        OAuth2Authentication authentication = (OAuth2Authentication) super.attemptAuthentication(request, response);

        String idToken = (String) super.restTemplate
                .getOAuth2ClientContext()
                .getAccessToken()
                .getAdditionalInformation().get("id_token");
        Assert.notNull(idToken, "id_token cannot be null");

        // Small hack here, preserves the id_token in the UserAuthentication Details map. Spring Security 5.1 will
        // provide native OpenID support, so it will be possible to refactor this in a better way
        Map<String, String> details = (Map<String, String>) authentication.getUserAuthentication().getDetails();
        details.put("id_token", idToken);

        return authentication;
    }
}
