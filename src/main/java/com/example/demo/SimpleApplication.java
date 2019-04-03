package com.example.demo;

import com.example.demo.auth.IdPortenClientAuthenticationProcessingFilter;
import com.example.demo.auth.IdPortenOidcEndpointLogoutHandler;
import com.example.demo.auth.IdPortenPrincipalExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@EnableOAuth2Client
@Controller
public class SimpleApplication extends WebSecurityConfigurerAdapter {

    @RequestMapping("/user")
    @ResponseBody
    public OAuth2Authentication user(OAuth2Authentication authentication) {
        return authentication;
    }

    @RequestMapping("/unauthenticated")
    public String unauthenticated() {
        return "redirect:/?error=true";
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .antMatcher("/**")
               .addFilterBefore(idPortenSsoFilter(), BasicAuthenticationFilter.class)
            .authorizeRequests()
               .antMatchers("/", "/login**", "/webjars/**", "/error**")
               .permitAll()
            .anyRequest()
               .authenticated()
            .and()
               .logout()
               .deleteCookies(("JSESSIONID"))
               .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
               .logoutSuccessHandler(idPortenOidcEndpointLogoutHandler)
            .permitAll()
            .and()
               .csrf()
               .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        // @formatter:on
    }

    @Configuration
    protected static class ServletCustomizer {
        @Bean
        public WebServerFactoryCustomizer<ConfigurableWebServerFactory> customizer() {
            return container -> {
                container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
            };
        }
    }

    @Bean
    @ConfigurationProperties("idporten.security.oauth2.client")
    public AuthorizationCodeResourceDetails idportenClient() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("idporten.security.oauth2.resource")
    public ResourceServerProperties idportenResource() {
        return new ResourceServerProperties();
    }

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private IdPortenOidcEndpointLogoutHandler idPortenOidcEndpointLogoutHandler;

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    private Filter idPortenSsoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List filters = new ArrayList<>();

        OAuth2ClientAuthenticationProcessingFilter idportenFilter =
                new IdPortenClientAuthenticationProcessingFilter("/login");

        OAuth2RestTemplate idportenTemplate = new OAuth2RestTemplate(idportenClient(), oauth2ClientContext);
        idportenFilter.setRestTemplate(idportenTemplate);

        UserInfoTokenServices tokenServices = new UserInfoTokenServices(idportenResource().getUserInfoUri(),
                idportenClient().getClientId());
        tokenServices.setPrincipalExtractor(new IdPortenPrincipalExtractor());
        tokenServices.setRestTemplate(idportenTemplate);

        idportenFilter.setTokenServices(tokenServices);

        filters.add(idportenFilter);
        filter.setFilters(filters);

        return filter;
    }

    public static void main(String[] args) {
        SpringApplication.run(SimpleApplication.class, args);
    }
}
