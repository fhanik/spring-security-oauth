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
package org.springframework.security.oauth2.provider;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * @author Filip Hanik
 */
public interface AuthorizationRedirectGenerator {

	String getSuccessfulRedirect(AuthorizationRequest authorizationRequest, String authorizationCode);

	String getUnsuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2Exception failure, boolean fragment);

	String getImplicitSuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken);
}
