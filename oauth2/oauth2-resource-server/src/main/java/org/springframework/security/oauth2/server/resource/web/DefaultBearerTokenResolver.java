/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.web;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;

/**
 * The default {@link BearerTokenResolver} implementation based on RFC 6750.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750 Section 2: Authenticated Requests</a>
 */
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

	private static final BearerTokenError BEARER_TOKEN_ERROR_MULTIPLE = new BearerTokenError(
			BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST,
			"Found multiple bearer tokens in the request", "https://tools.ietf.org/html/rfc6750#section-3.1");

	private static final BearerTokenError BEARER_TOKEN_ERROR_MALFORMED = new BearerTokenError(
			BearerTokenErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED, "Bearer token is malformed",
			"https://tools.ietf.org/html/rfc6750#section-3.1");

	private static final String ACCESS_TOKEN_PARAM_NAME = "access_token";

	private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+)=*$");

	private boolean allowFormEncodedBodyParameter = false;

	private boolean allowUriQueryParameter = false;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String resolve(HttpServletRequest request) {
		String authorizationHeaderToken = resolveFromAuthorizationHeader(request);
		validate(request, authorizationHeaderToken);
		return authorizationHeaderToken != null ? authorizationHeaderToken : resolveFromRequestParameters(request);
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported. Defaults to {@code false}.
	 * @param allowFormEncodedBodyParameter if the form-encoded body parameter is supported
	 */
	public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
		this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults to {@code false}.
	 *
	 * The spec recommends against using this mechanism for sending bearer tokens, and even goes as far as
	 * stating that it was only included for completeness.
	 *
	 * @param allowUriQueryParameter if the URI query parameter is supported
	 */
	public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
		this.allowUriQueryParameter = allowUriQueryParameter;
	}

	private void validate(final HttpServletRequest request, final String authorizationHeaderToken) {
		if (hasMultipleAccessTokens(request, authorizationHeaderToken)) {
			throw new OAuth2AuthenticationException(BEARER_TOKEN_ERROR_MULTIPLE);
		}
		if (this.allowFormEncodedBodyParameter) {
			if (!this.allowUriQueryParameter && isTokenInUriQueryParameter(request)) {
				throw new OAuth2AuthenticationException(BEARER_TOKEN_ERROR_MALFORMED);
			}
		}
	}

	private static String resolveFromAuthorizationHeader(HttpServletRequest request) {
		final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorization != null && authorization.startsWith("Bearer")) {
			final Matcher matcher = AUTHORIZATION_PATTERN.matcher(authorization);

			if (!matcher.matches()) {
				throw new OAuth2AuthenticationException(BEARER_TOKEN_ERROR_MALFORMED);
			}

			return matcher.group("token");
		}
		return null;
	}

	private String resolveFromRequestParameters(HttpServletRequest request) {
		// By this point there is either zero or one value
		final String value = request.getParameter(ACCESS_TOKEN_PARAM_NAME);
		if (value != null && isParameterTokenSupportedForRequest(request)) {
			return value;
		} else {
			return null;
		}
	}

	private boolean isParameterTokenSupportedForRequest(HttpServletRequest request) {
		return ((this.allowFormEncodedBodyParameter && "POST".equals(request.getMethod()))
				|| (this.allowUriQueryParameter && "GET".equals(request.getMethod())));
	}

	private boolean hasMultipleAccessTokens(final HttpServletRequest request, final String authorizationHeaderToken) {
		final String[] parameterTokens = request.getParameterValues(ACCESS_TOKEN_PARAM_NAME);
		final boolean multipleParameterTokensPresent = parameterTokens != null && parameterTokens.length > 1;
		final boolean bothParameterTokenAndHeaderPresent = parameterTokens != null && authorizationHeaderToken != null;
		return multipleParameterTokensPresent || bothParameterTokenAndHeaderPresent;
	}

	private boolean isTokenInUriQueryParameter(final HttpServletRequest request) {
		final String queryString = request.getQueryString();
		return queryString != null && Arrays.stream(queryString.split("&"))
				.map(param -> urlDecodeUTF8(param.split("=")[0]))
				.anyMatch(Predicate.isEqual(ACCESS_TOKEN_PARAM_NAME));
	}

	private String urlDecodeUTF8(final String value) {
		try {
			return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			return value;
		}
	}

}
