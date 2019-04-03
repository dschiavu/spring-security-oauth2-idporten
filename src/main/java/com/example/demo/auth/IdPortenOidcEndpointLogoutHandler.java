package com.example.demo.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.ResourceUtils;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * A logout handler for coordinating logout with the ID-porten OIDC OP through the user agent.
 * <p>
 * Redirects the user to the /endsession endpoint passing the {@code id_token_hint} parameter so that we can end the
 * session with the OP and get redirected back to the app.
 * <p>
 * Note: replace this custom implementation when Spring Security 5.1 is released (via Boot) which will include
 * native support for the endsession endpoint, see the following tasks:
 * <p>
 * https://github.com/spring-projects/spring-security/issues/5350
 * https://github.com/spring-projects/spring-security/pull/5356
 * and https://github.com/spring-projects/spring-security/issues/5415
 *
 * @see <a href="http://openid.net/specs/openid-connect-session-1_0.html#RPLogout">RP-Initiated Logout</a>
 * @see <a href="https://difi.github.io/idporten-oidc-dokumentasjon/oidc_func_sso.html">ID-porten SSO</a>
 */
@Component
public class IdPortenOidcEndpointLogoutHandler implements LogoutSuccessHandler {

    @Value("${idporten.security.oauth2.client.endSessionUri}")
    private String oidcLogoutEndpointUrl;

    @Value("${idporten.security.oauth2.client.postLogoutRedirectUri}")
    private String postLogoutRedirectUri;

    public IdPortenOidcEndpointLogoutHandler() {
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        Assert.notNull(oidcLogoutEndpointUrl, "oidcLogoutEndpointUrl cannot be null");
        Assert.isTrue(ResourceUtils.isUrl(oidcLogoutEndpointUrl), "oidcLogoutEndpointUrl must be a valid URL");

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(this.oidcLogoutEndpointUrl);

        if (authentication instanceof OAuth2Authentication) {
            builder.queryParam("id_token_hint", idToken(authentication));
        }

        if (this.postLogoutRedirectUri != null) {
            Assert.isTrue(ResourceUtils.isUrl(postLogoutRedirectUri),
                    "postLogoutRedirectUri must be a valid URL");
            builder.queryParam("post_logout_redirect_uri", this.postLogoutRedirectUri);
        }

        response.sendRedirect(builder.toUriString());
    }

    private String idToken(Authentication authentication) {
        OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
        Map<String, String> details = (Map<String, String>) oAuth2Authentication.getUserAuthentication().getDetails();
        String idToken = details.get("id_token");

        Assert.notNull(idToken, "id_token cannot be null");

        return idToken;
    }
}
