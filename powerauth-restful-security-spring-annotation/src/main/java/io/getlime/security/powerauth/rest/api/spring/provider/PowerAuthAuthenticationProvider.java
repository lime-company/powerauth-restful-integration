/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.getlime.security.powerauth.rest.api.spring.provider;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.http.validator.PowerAuthTokenHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthHeaderMissingException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthTokenInvalidException;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthApiAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthSignatureAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthTokenAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.converter.v3.SignatureTypeConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Implementation of PowerAuth authentication provider.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@Component
public class PowerAuthAuthenticationProvider extends PowerAuthAuthenticationProviderBase {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAuthenticationProvider.class);

    private PowerAuthClient powerAuthClient;

    /**
     * Set PowerAuth service client via setter injection.
     *
     * @param powerAuthClient PowerAuth service client.
     */
    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Authenticate user using the provided authentication.
     *
     * @param authentication Authentication used to verify the user.
     * @return Authentication with the authenticated user details.
     * @throws AuthenticationException In case authentication fails.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Handle signature based authentications
        if (authentication instanceof PowerAuthSignatureAuthenticationImpl) {
            return validateSignatureAuthentication((PowerAuthSignatureAuthenticationImpl) authentication);
        }
        // Handle basic token-based authentications
        else if (authentication instanceof PowerAuthTokenAuthenticationImpl) {
            return validateTokenAuthentication((PowerAuthTokenAuthenticationImpl) authentication);
        }
        // Return null in case unknown authentication type is provided
        return null;
    }

    /**
     * Validate signature based authentication.
     *
     * @param authentication Signature based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthenticationImpl validateSignatureAuthentication(PowerAuthSignatureAuthenticationImpl authentication) {

        if (authentication.getSignatureType() != null) {

            final SignatureTypeConverter converter = new SignatureTypeConverter();
            final SignatureType signatureType = converter.convertFrom(authentication.getSignatureType());
            if (signatureType == null) {
                return null;
            }

            final VerifySignatureRequest request = new VerifySignatureRequest();
            request.setActivationId(authentication.getActivationId());
            request.setApplicationKey(authentication.getApplicationKey());
            request.setSignature(authentication.getSignature());
            request.setSignatureType(signatureType);
            request.setSignatureVersion(authentication.getVersion());
            request.setData(PowerAuthHttpBody.getSignatureBaseString(
                    authentication.getHttpMethod(),
                    authentication.getRequestUri(),
                    authentication.getNonce(),
                    authentication.getData()
            ));

            // In case forced signature version is specified, use it in the request.
            // This occurs when verifying signature during upgrade before upgrade is committed.
            if (authentication.getForcedSignatureVersion() != null) {
                request.setForcedSignatureVersion(authentication.getForcedSignatureVersion().longValue());
            }

            final VerifySignatureResponse response;
            try {
                response = powerAuthClient.verifySignature(request);
            } catch (PowerAuthClientException ex) {
                logger.warn("Signature validation failed, error: {}", ex.getMessage());
                logger.debug("Error details", ex);
                return null;
            }
            if (response.isSignatureValid()) {
                return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                        response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(), PowerAuthSignatureTypes.getEnumFromString(response.getSignatureType().value()),
                        authentication.getVersion(), authentication.getHttpHeader());
            } else {
                return null;
            }

        } else {
            return null;
        }
    }

    /**
     * Validate basic token-based authentication.
     *
     * @param authentication Token based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthenticationImpl validateTokenAuthentication(PowerAuthTokenAuthenticationImpl authentication) {
        try {
            final ValidateTokenRequest soapRequest = new ValidateTokenRequest();
            soapRequest.setTokenId(authentication.getTokenId());
            soapRequest.setTokenDigest(authentication.getTokenDigest());
            soapRequest.setNonce(authentication.getNonce());
            soapRequest.setTimestamp(Long.parseLong(authentication.getTimestamp()));

            final ValidateTokenResponse soapResponse = powerAuthClient.validateToken(soapRequest);
            if (soapResponse.isTokenValid()) {
                return copyAuthenticationAttributes(soapResponse.getActivationId(), soapResponse.getUserId(),
                        soapResponse.getApplicationId(), soapResponse.getApplicationRoles(), soapResponse.getActivationFlags(), PowerAuthSignatureTypes.getEnumFromString(soapResponse.getSignatureType().value()),
                        authentication.getVersion(), authentication.getHttpHeader());
            } else {
                return null;
            }
        } catch (NumberFormatException ex) {
            logger.warn("Invalid timestamp format, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        } catch (Exception ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
    }

    /**
     * Prepare API initialized authentication object with provided authentication attributes.
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @param activationFlags Activation flags.
     * @param signatureType Signature Type.
     * @param version PowerAuth protocol version.
     * @param httpHeader Raw PowerAuth http header.
     * @return Initialized instance of API authentication.
     */
    private PowerAuthApiAuthenticationImpl copyAuthenticationAttributes(String activationId, String userId, Long applicationId, List<String> applicationRoles,
                                                                        List<String> activationFlags, PowerAuthSignatureTypes signatureType, String version,
                                                                        PowerAuthHttpHeader httpHeader) {
        final PowerAuthApiAuthenticationImpl apiAuthentication = new PowerAuthApiAuthenticationImpl();
        apiAuthentication.setActivationId(activationId);
        apiAuthentication.setUserId(userId);
        apiAuthentication.setApplicationId(applicationId);
        apiAuthentication.setApplicationRoles(applicationRoles);
        apiAuthentication.setActivationFlags(activationFlags);
        apiAuthentication.setSignatureFactors(signatureType);
        apiAuthentication.setAuthenticated(true);
        apiAuthentication.setVersion(version);
        apiAuthentication.setHttpHeader(httpHeader);
        return apiAuthentication;
    }

    /**
     * Validate the signature from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed signatures.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @param forcedSignatureVersion Forced signature version, optional parameter used during upgrade.
     * @return Instance of a PowerAuthApiAuthenticationImpl on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(
            String httpMethod,
            byte[] httpBody,
            String requestUriIdentifier,
            String httpAuthorizationHeader,
            List<PowerAuthSignatureTypes> allowedSignatureTypes,
            @Nullable Integer forcedSignatureVersion
    ) throws PowerAuthAuthenticationException {

        // Check for HTTP PowerAuth signature header
        if (httpAuthorizationHeader == null || httpAuthorizationHeader.equals("undefined")) {
            logger.warn("Signature HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(httpAuthorizationHeader);

        // Validate the header
        try {
            PowerAuthSignatureHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSignatureInvalidException();
        }

        // Check if the signature type is allowed
        final PowerAuthSignatureTypes expectedSignatureType = PowerAuthSignatureTypes.getEnumFromString(header.getSignatureType());
        if (expectedSignatureType == null || !allowedSignatureTypes.contains(expectedSignatureType)) {
            logger.warn("Invalid signature type: {}", expectedSignatureType);
            throw new PowerAuthSignatureTypeInvalidException();
        }

        // Configure PowerAuth authentication object
        final PowerAuthSignatureAuthenticationImpl powerAuthAuthentication = new PowerAuthSignatureAuthenticationImpl();
        powerAuthAuthentication.setActivationId(header.getActivationId());
        powerAuthAuthentication.setApplicationKey(header.getApplicationKey());
        powerAuthAuthentication.setNonce(BaseEncoding.base64().decode(header.getNonce()));
        powerAuthAuthentication.setSignatureType(header.getSignatureType());
        powerAuthAuthentication.setSignature(header.getSignature());
        powerAuthAuthentication.setHttpMethod(httpMethod);
        powerAuthAuthentication.setRequestUri(requestUriIdentifier);
        powerAuthAuthentication.setData(httpBody);
        powerAuthAuthentication.setVersion(header.getVersion());
        powerAuthAuthentication.setHttpHeader(header);
        powerAuthAuthentication.setForcedSignatureVersion(forcedSignatureVersion);

        // Call the authentication based on signature authentication object
        final PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }

        return auth;
    }

    /**
     * Validate token header for simple token-based authentication.
     *
     * @param tokenHeader Token header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @return Authentication object in case authentication is correctly obtained.
     * @throws PowerAuthAuthenticationException In case of authentication failure.
     */
    public PowerAuthApiAuthentication validateToken(String tokenHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException {

        // Check for HTTP PowerAuth signature header
        if (tokenHeader == null || tokenHeader.equals("undefined")) {
            logger.warn("Token HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        final PowerAuthTokenHttpHeader header = new PowerAuthTokenHttpHeader().fromValue(tokenHeader);

        // Validate the header
        try {
            PowerAuthTokenHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenInvalidException();
        }

        // Prepare authentication object
        final PowerAuthTokenAuthenticationImpl powerAuthTokenAuthentication = new PowerAuthTokenAuthenticationImpl();
        powerAuthTokenAuthentication.setTokenId(header.getTokenId());
        powerAuthTokenAuthentication.setTokenDigest(header.getTokenDigest());
        powerAuthTokenAuthentication.setNonce(header.getNonce());
        powerAuthTokenAuthentication.setTimestamp(header.getTimestamp());
        powerAuthTokenAuthentication.setVersion(header.getVersion());
        powerAuthTokenAuthentication.setHttpHeader(header);

        // Call the authentication based on token authentication object
        final PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthTokenAuthentication);

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Invalid token value");
            throw new PowerAuthTokenInvalidException();
        }

        // Check if the signature type is allowed
        final PowerAuthSignatureTypes expectedSignatureType = auth.getSignatureFactors();
        if (expectedSignatureType == null || !allowedSignatureTypes.contains(expectedSignatureType)) {
            logger.warn("Invalid signature type in token validation: {}", expectedSignatureType);
            throw new PowerAuthSignatureTypeInvalidException();
        }

        return auth;

    }

}
