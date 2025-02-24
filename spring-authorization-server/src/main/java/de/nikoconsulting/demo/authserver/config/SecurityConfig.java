package de.nikoconsulting.demo.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import de.nikoconsulting.demo.authserver.security.authentication.OAuth2TokenExchangeFederatedAuthenticationProvider;
import de.nikoconsulting.demo.authserver.security.oauth2.server.authorization.token.MyJwtCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                // TODO: configure JdbcRegisteredClientRepository
                                //.registeredClientRepository(registeredClientRepository)
                                /**
                                 * The OAuth2AuthorizationService is an OPTIONAL component and defaults to InMemoryOAuth2AuthorizationService.
                                 * The InMemoryOAuth2AuthorizationService implementation stores OAuth2Authorization instances in-memory and is
                                 * recommended ONLY to be used during development and testing. JdbcOAuth2AuthorizationService is a JDBC implementation
                                 * that persists OAuth2Authorization instances by using JdbcOperations.
                                 *
                                 * TODO: configure JdbcOAuth2AuthorizationService
                                 */
                                .authorizationService(authorizationService())
                                //.authorizationConsentService(authorizationConsentService)
                                .authorizationServerSettings(authorizationServerSettings())
                                .tokenGenerator(tokenGenerator())
                                .tokenEndpoint(tokenEndpoint ->
                                                       tokenEndpoint
                                                               .authenticationProvider(tokenExchangeFederatedAuthenticationProvider(authorizationService(), tokenGenerator()))

                                )

                );

        return http.build();
    }

    @Bean
    public AuthenticationProvider tokenExchangeFederatedAuthenticationProvider(OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        JwtDecoder jwtDecoder = oidcJwtDecoder();
        return  new OAuth2TokenExchangeFederatedAuthenticationProvider(authorizationService, tokenGenerator, jwtDecoder);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return  new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        JwtEncoder jwtEncoder = jwtEncoder(jwkSource());
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer());
        //no opaque access_token
        //no refresh_token
        //only JWT access_token
        return new DelegatingOAuth2TokenGenerator(jwtGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        JwtDecoder jwtDecoder = oidcJwtDecoder();
        return new MyJwtCustomizer(jwtDecoder);
    }

    // ####################################################################
    // JWT Configuration
    // ####################################################################
    /**
     *
     * @return An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     *
     * @return An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
        return keyPair;
    }

    /**
     * By Default instantiated by Spring
     * @param jwkSource
     * @return An instance of JwtDecoder for decoding signed access tokens.
     */
    //@Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // ##########################################################################
    // PPN JWT Configuration (validate JWT issued by PPN during TokenExchange
    // ##########################################################################

    @Value("${spring.security.oauth2.authorization-server.federation.main-server.issuer-uri}")
    private String oidcIssuerUri;

    /**
     * An instance of JwtDecoder for decoding PPN signed access tokens.
     * @return
     */
    //@Bean
    public JwtDecoder oidcJwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(oidcIssuerUri).build();
        OAuth2TokenValidator<Jwt> withClockSkew = new JwtTimestampValidator(Duration.ofSeconds(60));
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(oidcIssuerUri);

        OAuth2TokenValidator<Jwt> customValidators = new DelegatingOAuth2TokenValidator<>(
                withClockSkew,
                withIssuer
        );

        jwtDecoder.setJwtValidator(customValidators);
        return jwtDecoder;
    }

}
