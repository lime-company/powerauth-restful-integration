/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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
import com.wultra.security.powerauth.client.v3.ConfirmRecoveryCodeResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthRecoveryConfirmationException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing recovery functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class RecoveryService {

    private static final Logger logger = LoggerFactory.getLogger(RecoveryService.class);

    private final PowerAuthClient powerAuthClient;

    /**
     * Controller constructor.
     * @param powerAuthClient PowerAuth client.
     */
    @Autowired
    public RecoveryService(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Confirm recovery code.
     * @param request ECIES encrypted request.
     * @param authentication PowerAuth API authentication object.
     * @return ECIES encrypted response.
     * @throws PowerAuthAuthenticationException In case confirm recovery fails.
     */
    public EciesEncryptedResponse confirmRecoveryCode(EciesEncryptedRequest request,
                                                      PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            final String activationId = authentication.getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();
            if (activationId == null || applicationKey == null || request.getEphemeralPublicKey() == null
                    || request.getEncryptedData() == null || request.getMac() == null) {
                logger.warn("PowerAuth confirm recovery failed because of invalid request");
                throw new PowerAuthInvalidRequestException();
            }
            final ConfirmRecoveryCodeResponse paResponse = powerAuthClient.confirmRecoveryCode(activationId, applicationKey,
                    request.getEphemeralPublicKey(), request.getEncryptedData(), request.getMac(), request.getNonce());
            if (!paResponse.getActivationId().equals(activationId)) {
                logger.warn("PowerAuth confirm recovery failed because of invalid activation ID in response");
                throw new PowerAuthInvalidRequestException();
            }
            return new EciesEncryptedResponse(paResponse.getEncryptedData(), paResponse.getMac());
        } catch (Exception ex) {
            logger.warn("PowerAuth confirm recovery failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthRecoveryConfirmationException();
        }
    }
}
