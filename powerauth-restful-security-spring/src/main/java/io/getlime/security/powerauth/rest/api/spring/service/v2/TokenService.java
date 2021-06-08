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
package io.getlime.security.powerauth.rest.api.spring.service.v2;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v2.CreateTokenResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthTokenErrorException;
import io.getlime.security.powerauth.rest.api.model.request.v2.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.spring.converter.v2.SignatureTypeConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing token functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("tokenServiceV2")
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
     * @param request Create token request.
     * @param authentication PowerAuth API authentication.
     * @return Create token response.
     * @throws PowerAuthAuthenticationException In case token could not be created.
     */
    public TokenCreateResponse createToken(TokenCreateRequest request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            // Fetch activation ID and signature type
            final String activationId = authentication.getActivationId();
            final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();

            // Prepare a signature type converter
            SignatureTypeConverter converter = new SignatureTypeConverter();

            // Create a token
            final CreateTokenResponse token = powerAuthClient.v2().createToken(activationId, ephemeralPublicKey, converter.convertFrom(signatureFactors));

            // Prepare a response
            final TokenCreateResponse response = new TokenCreateResponse();
            response.setMac(token.getMac());
            response.setEncryptedData(token.getEncryptedData());
            return response;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth token failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenErrorException();
        }
    }

}
