package de.nikoconsulting.demo.authserver.security.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

public class OAuth2TokenExchangeFederatedAuthenticationProvider implements AuthenticationProvider {


    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

    private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

    private static final String MAY_ACT = "may_act";

    private final Log logger = LogFactory.getLog(getClass());

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final JwtDecoder jwtDecoder;

    private Consumer<OAuth2TokenExchangeAuthenticationContext> authenticationValidator = new OAuth2TokenExchangeFederatedAuthenticationValidator();

    /**
     * Constructs an {@code OAuth2TokenExchangeAuthenticationProvider} using the provided
     * parameters.
     *
     * @param authorizationService the authorization service
     * @param tokenGenerator       the token generator
     */
    public OAuth2TokenExchangeFederatedAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                              OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, JwtDecoder jwtDecoder) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.jwtDecoder = jwtDecoder;
    }

    private Jwt validateToken(OAuth2TokenExchangeAuthenticationContext authenticationContext) {
        OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = authenticationContext.getAuthentication();
        //RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        try {
            return this.jwtDecoder.decode(tokenExchangeAuthentication.getSubjectToken()); //
        } catch (Exception e) {
            this.logger.error(e);
        }
        return null;
    }

    private static boolean isValidTokenType(String tokenType, OAuth2Authorization.Token<OAuth2Token> token) {
        String tokenFormat = token.getMetadata(OAuth2TokenFormat.class.getName());
        return ACCESS_TOKEN_TYPE_VALUE.equals(tokenType) || JWT_TOKEN_TYPE_VALUE.equals(tokenType)
                && OAuth2TokenFormat.SELF_CONTAINED.getValue()
                .equals(tokenFormat);
    }

    private static Set<String> validateRequestedScopes(RegisteredClient registeredClient, Set<String> requestedScopes) {
        for (String requestedScope : requestedScopes) {
            if (!registeredClient.getScopes()
                    .contains(requestedScope)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        }

        return new LinkedHashSet<>(requestedScopes);
    }

    private static void validateClaims(Map<String, Object> expectedClaims, Map<String, Object> actualClaims,
                                       String... claimNames) {
        if (actualClaims == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        for (String claimName : claimNames) {
            if (!Objects.equals(expectedClaims.get(claimName), actualClaims.get(claimName))) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = (OAuth2TokenExchangeAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
                .getAuthenticatedClientElseThrowInvalidClient(tokenExchangeAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.TOKEN_EXCHANGE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        if (JWT_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getRequestedTokenType())
                && !OAuth2TokenFormat.SELF_CONTAINED
                .equals(registeredClient.getTokenSettings()
                                .getAccessTokenFormat())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // here comes the validation of the token against the external issuer
        OAuth2TokenExchangeAuthenticationContext authenticationContext = OAuth2TokenExchangeAuthenticationContext
                .with(tokenExchangeAuthentication)
                .registeredClient(registeredClient)
                .build();
        //this.authenticationValidator.accept(authenticationContext);
        Jwt validatedToken = validateToken(authenticationContext);
        if (validatedToken == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        Set<String> authorizedScopes = Collections.emptySet();
        if (!CollectionUtils.isEmpty(tokenExchangeAuthentication.getScopes())) {
            authorizedScopes = validateRequestedScopes(registeredClient, tokenExchangeAuthentication.getScopes());
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated token request parameters");
        }

        //Authentication principal = getPrincipal(subjectAuthorization, null);
        // Authentication principal = tokenExchangeAuthentication;
        // @formatter:off
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(tokenExchangeAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrant(tokenExchangeAuthentication)
                .put(Jwt.class, validatedToken);
        // @formatter:on


        // ----- Access token -----
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                                                "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        // @formatter:off
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(tokenExchangeAuthentication.getName())
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), tokenExchangeAuthentication);
        // @formatter:on

        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder,
                                                                                      generatedAccessToken, tokenContext);

        OAuth2Authorization authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.ISSUED_TOKEN_TYPE,
                                 tokenExchangeAuthentication.getRequestedTokenType());

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated token request");
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null,
                                                        additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Sets the {@code Consumer} providing access to the
     * {@link OAuth2ClientCredentialsAuthenticationContext} and is responsible for
     * validating specific OAuth 2.0 Client Credentials Grant Request parameters
     * associated in the {@link OAuth2ClientCredentialsAuthenticationToken}. The default
     * authentication validator is {@link OAuth2ClientCredentialsAuthenticationValidator}.
     *
     * <p>
     * <b>NOTE:</b> The authentication validator MUST throw
     * {@link OAuth2AuthenticationException} if validation fails.
     *
     * @param authenticationValidator the {@code Consumer} providing access to the
     *                                {@link OAuth2ClientCredentialsAuthenticationContext} and is responsible for
     *                                validating specific OAuth 2.0 Client Credentials Grant Request parameters
     * @since 1.3
     */
    public void setAuthenticationValidator(
            Consumer<OAuth2TokenExchangeAuthenticationContext> authenticationValidator) {
        Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
        this.authenticationValidator = authenticationValidator;
    }
}
