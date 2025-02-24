/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.nikoconsulting.demo.authserver.security.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Consumer;

/**
 * A {@code Consumer} providing access to the
 * {@link OAuth2ClientCredentialsAuthenticationContext} containing an
 * {@link OAuth2ClientCredentialsAuthenticationToken} and is the default
 * {@link OAuth2ClientCredentialsAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OAuth 2.0 Client Credentials
 * Grant Request parameters.
 *
 * <p>
 * The default implementation validates
 * {@link OAuth2ClientCredentialsAuthenticationToken#getScopes()}. If validation fails, an
 * {@link OAuth2AuthenticationException} is thrown.
 *
 * @author Adam Pilling
 * @since 1.3
 * @see OAuth2ClientCredentialsAuthenticationContext
 * @see OAuth2ClientCredentialsAuthenticationToken
 * @see OAuth2ClientCredentialsAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2TokenExchangeFederatedAuthenticationValidator
		implements Consumer<OAuth2TokenExchangeAuthenticationContext> {

	private static final Log LOGGER = LogFactory.getLog(OAuth2TokenExchangeFederatedAuthenticationValidator.class);

	/**
	 * The default validator for
	 * {@link OAuth2ClientCredentialsAuthenticationToken#getScopes()}.
	 */
	public static final Consumer<OAuth2TokenExchangeAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OAuth2TokenExchangeFederatedAuthenticationValidator::validateToken;

	private final Consumer<OAuth2TokenExchangeAuthenticationContext> authenticationValidator = DEFAULT_SCOPE_VALIDATOR;

	@Override
	public void accept(OAuth2TokenExchangeAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateToken(OAuth2TokenExchangeAuthenticationContext authenticationContext) {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = authenticationContext.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
		// extract
		String subjectToken = tokenExchangeAuthentication.getSubjectToken();

	}

}
