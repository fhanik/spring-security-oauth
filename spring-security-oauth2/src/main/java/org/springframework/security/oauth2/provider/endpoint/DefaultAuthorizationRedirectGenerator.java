/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRedirectGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriTemplate;

/**
 * @author Filip Hanik
 */
public class DefaultAuthorizationRedirectGenerator implements AuthorizationRedirectGenerator {
	@Override
	public String getSuccessfulRedirect(AuthorizationRequest authorizationRequest, String authorizationCode) {
		if (authorizationCode == null) {
			throw new IllegalStateException("No authorization code found in the current request scope.");
		}

		UriComponentsBuilder template = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri());
		template.queryParam("code", authorizationCode);

		String state = authorizationRequest.getState();
		if (state != null) {
			template.queryParam("state", state);
		}

		return template.build().encode().toUriString();
	}

	@Override
	public String getUnsuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2Exception failure, boolean fragment) {
		if (authorizationRequest == null || authorizationRequest.getRedirectUri() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		UriComponentsBuilder template = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri());
		Map<String, String> query = new LinkedHashMap<String, String>();
		StringBuilder values = new StringBuilder();

		values.append("error={error}");
		query.put("error", failure.getOAuth2ErrorCode());

		values.append("&error_description={error_description}");
		query.put("error_description", failure.getMessage());

		if (authorizationRequest.getState() != null) {
			values.append("&state={state}");
			query.put("state", authorizationRequest.getState());
		}

		if (failure.getAdditionalInformation() != null) {
			for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
				values.append("&" + additionalInfo.getKey() + "={" + additionalInfo.getKey() + "}");
				query.put(additionalInfo.getKey(), additionalInfo.getValue());
			}
		}

		if (fragment) {
			template.fragment(values.toString());
		}
		else {
			template.query(values.toString());
		}

		return template.build().expand(query).encode().toUriString();
	}

	@Override
	public String getImplicitSuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {
		Map<String, Object> vars = new HashMap<String, Object>();

		String requestedRedirect = authorizationRequest.getRedirectUri();
		if (accessToken == null) {
			throw new InvalidRequestException("An implicit grant could not be made");
		}
		StringBuilder url = new StringBuilder(requestedRedirect);
		if (requestedRedirect.contains("#")) {
			url.append("&");
		}
		else {
			url.append("#");
		}

		url.append("access_token={access_token}");
		url.append("&token_type={token_type}");
		vars.put("access_token", accessToken.getValue());
		vars.put("token_type", accessToken.getTokenType());
		String state = authorizationRequest.getState();

		if (state != null) {
			url.append("&state={state}");
			vars.put("state", state);
		}
		Date expiration = accessToken.getExpiration();
		if (expiration != null) {
			long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
			url.append("&expires_in={expires_in}");
			vars.put("expires_in", expires_in);
		}
		String originalScope = authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE);
		if (originalScope == null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
			url.append("&" + OAuth2Utils.SCOPE + "={scope}");
			vars.put("scope", OAuth2Utils.formatParameterList(accessToken.getScope()));
		}
		Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
		for (String key : additionalInformation.keySet()) {
			Object value = additionalInformation.get(key);
			if (value != null) {
				url.append("&" + key + "={extra_" + key + "}");
				vars.put("extra_" + key, value);
			}
		}
		UriTemplate template = new UriTemplate(url.toString());
		// Do not include the refresh token (even if there is one)
		return template.expand(vars).toString();
	}
}
