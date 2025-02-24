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

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2ClientCredentialsAuthenticationToken} and additional information and is
 * used when validating the OAuth 2.0 Token Exchange Grant Request.
 *
 * @author
 * @see OAuth2AuthenticationContext
 * @see OAuth2TokenExchangeAuthenticationToken
 * @see OAuth2TokenExchangeFederatedAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2TokenExchangeAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2TokenExchangeAuthenticationContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2ClientCredentialsAuthenticationToken}.
	 * @param authentication the {@link OAuth2ClientCredentialsAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2TokenExchangeAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2TokenExchangeAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2TokenExchangeAuthenticationContext, Builder> {

		private Builder(OAuth2TokenExchangeAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link RegisteredClient registered client}.
		 * @param registeredClient the {@link RegisteredClient}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder registeredClient(RegisteredClient registeredClient) {
			return put(RegisteredClient.class, registeredClient);
		}

		/**
		 * Builds a new {@link OAuth2TokenExchangeAuthenticationContext}.
		 * @return the {@link OAuth2TokenExchangeAuthenticationContext}
		 */
		public OAuth2TokenExchangeAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			return new OAuth2TokenExchangeAuthenticationContext(getContext());
		}

	}

}
