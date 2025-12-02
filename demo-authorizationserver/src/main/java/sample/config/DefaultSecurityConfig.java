/*
 * Copyright 2020-2023 the original author or authors.
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
package sample.config;

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.1
 */
@EnableWebSecurity
@EnableMultiFactorAuthentication(authorities = {})
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultSecurityConfig.class);

	// @formatter:off
	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/assets/**", "/login").permitAll()
					.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin(Customizer.withDefaults());

		return http.build();
	}
	// @formatter:on

	@Bean
	public OneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler() {
		RedirectOneTimeTokenGenerationSuccessHandler delegate = new RedirectOneTimeTokenGenerationSuccessHandler("/login/ott");
		return (request, response, oneTimeToken) -> {
			LOGGER.info("Generated one-time token for request {}: {}", request.getRequestURI(), oneTimeToken.getTokenValue());
			delegate.handle(request, response, oneTimeToken);
		};
	}

	@Bean
	public AuthorizationManagerFactory<Object> authorizationManagerFactory() {
		DefaultAuthorizationManagerFactory<Object> result = new DefaultAuthorizationManagerFactory<>();
		result.setAdditionalAuthorization(new MfaAuthorizationManager());
		return result;
	}

	private static final class MfaAuthorizationManager implements AuthorizationManager<Object> {

		private final AuthorizationManager<Object> requiredFactorsAuthorizationManager =
				AllRequiredFactorsAuthorizationManager.builder()
						.requireFactor(RequiredFactor.builder().passwordAuthority().build())
						.requireFactor(RequiredFactor.builder().ottAuthority().build())
						.build();

		@Override
		public @Nullable AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authenticationSupplier, Object object) {
			Authentication authentication = authenticationSupplier.get();
			if (authentication instanceof OAuth2ClientAuthenticationToken ||
					authentication instanceof AbstractOAuth2TokenAuthenticationToken) {
				// MFA is not required for OAuth2 Client Authentication OR OAuth2 Bearer Authentication
				return null;
			}
			return this.requiredFactorsAuthorizationManager.authorize(authenticationSupplier, object);
		}

	}

	// @formatter:off
	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	// @formatter:on

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

}
