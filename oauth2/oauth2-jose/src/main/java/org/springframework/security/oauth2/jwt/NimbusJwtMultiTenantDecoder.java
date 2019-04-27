/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import java.net.URI;
import java.text.ParseException;
import java.util.Map;

/**
 * A low-level Nimbus implementation of {@link JwtDecoder} which takes a raw Nimbus configuration.
 *
 * @author Gladwin Burboz
 * @since 5.2
 */
public class NimbusJwtMultiTenantDecoder implements JwtDecoder {

	private Map<URI, NimbusJwtDecoder> issuerToDecoderMap;

	public NimbusJwtMultiTenantDecoder(Map<URI, NimbusJwtDecoder> issuerToDecoderMap) {
		this.issuerToDecoderMap = issuerToDecoderMap;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		try {
			JWT jwt = JWTParser.parse(token);
			URI issuer = URI.create(jwt.getJWTClaimsSet().getIssuer());
			return issuerToDecoderMap.get(issuer).decode(token, jwt);
		} catch (ParseException e) {
			throw new JwtException(String.format(
					NimbusJwtDecoder.DECODING_ERROR_MESSAGE_TEMPLATE, e.getMessage()), e);
		}
	}

}
