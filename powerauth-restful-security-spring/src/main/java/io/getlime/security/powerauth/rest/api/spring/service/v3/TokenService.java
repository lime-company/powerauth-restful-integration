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
package io.getlime.security.powerauth.rest.api.spring.service.v3;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.CreateTokenResponse;
import com.wultra.security.powerauth.client.v3.SignatureType;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthTokenErrorException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.TokenRemoveResponse;
import io.getlime.security.powerauth.rest.api.spring.converter.v3.SignatureTypeConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing token functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("tokenServiceV3")
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    private PowerAuthClient powerAuthClient;

    /**
     * Set PowerAuth service client via setter injection.
     * @param powerAuthClient PowerAuth service client.
     */
    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Create token.
     *
     * @param request        ECIES encrypted create token request.
     * @param authentication PowerAuth API authentication object.
     * @return ECIES encrypted create token response.
     * @throws PowerAuthAuthenticationException In case token could not be created.
     */
    public EciesEncryptedResponse createToken(EciesEncryptedRequest request,
                                              PowerAuthApiAuthentication authentication)
            throws PowerAuthAuthenticationException {
        try {
            // Fetch activation ID and signature type
            final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();
            final String nonce = request.getNonce();

            // Prepare a signature type converter
            final SignatureTypeConverter converter = new SignatureTypeConverter();
            final SignatureType signatureType = converter.convertFrom(signatureFactors);
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", signatureFactors);
                throw new PowerAuthSignatureTypeInvalidException();
            }

            // Get ECIES headers
            final String activationId = authentication.getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Create a token
            final CreateTokenResponse token = powerAuthClient.createToken(activationId, applicationKey, ephemeralPublicKey,
                    encryptedData, mac, nonce, signatureType);

            // Prepare a response
            final EciesEncryptedResponse response = new EciesEncryptedResponse();
            response.setMac(token.getMac());
            response.setEncryptedData(token.getEncryptedData());
            return response;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth token failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenErrorException();
        }
    }

    /**
     * Remove token.
     *
     * @param request        Remove token request.
     * @param authentication PowerAuth API authentication object.
     * @return Remove token response.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public TokenRemoveResponse removeToken(TokenRemoveRequest request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            // Fetch activation ID
            final String activationId = authentication.getActivationId();

            // Fetch token ID from the request
            final String tokenId = request.getTokenId();

            // Remove a token, ignore response, since the endpoint should quietly return
            powerAuthClient.removeToken(tokenId, activationId);

            // Prepare a response
            final TokenRemoveResponse response = new TokenRemoveResponse();
            response.setTokenId(tokenId);
            return response;
        } catch (Exception ex) {
            logger.warn("Removing PowerAuth token failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenErrorException();
        }
    }
}
