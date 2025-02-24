package de.nikoconsulting.demo.authserver.security.oauth2.server.authorization.token;

import de.nikoconsulting.demo.authserver.security.authentication.OAuth2TokenExchangeAuthenticationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class MyJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final Log logger = LogFactory.getLog(getClass());

    private final JwtDecoder jwtDecoder;

    public MyJwtCustomizer(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }


    @Override
    public void customize(JwtEncodingContext context) {
        JwsHeader.Builder headers = context.getJwsHeader();
        JwtClaimsSet.Builder claims = context.getClaims();
        if (context.getTokenType()
                .equals(OAuth2TokenType.ACCESS_TOKEN)) {
            // Customize headers/claims for access_token
            // TODO: impl
            claims.claim("issued_by", "Custom Spring OAuth2 Authorization Server");
            claims.claim("client_id", context.getRegisteredClient()
                    .getClientId());

            if (context.getPrincipal() instanceof OAuth2TokenExchangeAuthenticationToken) {
                Jwt validatedToken = validateToken(context.getPrincipal());
                if (validatedToken == null) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
                }

                final String username = validatedToken.getClaims()
                        .get("preferred_username") != null ? validatedToken.getClaims()
                        .get("preferred_username")
                        .toString() : "user_unknown";

                // Add custom claims based on the validated identity
                claims.claim("username", username);
                claims.claim("exchange_source", "External OIDC Provider: " + validatedToken.getIssuer());
            }
        }
    }

    private Jwt validateToken(OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication) {
          try {
            return this.jwtDecoder.decode(tokenExchangeAuthentication.getSubjectToken()); //
        } catch (Exception e) {
            this.logger.error(e);
        }
        return null;
    }
}
