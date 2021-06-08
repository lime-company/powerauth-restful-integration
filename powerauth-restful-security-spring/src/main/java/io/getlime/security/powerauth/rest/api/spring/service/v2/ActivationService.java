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
import com.wultra.security.powerauth.client.v2.PrepareActivationResponse;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing activation functionality.
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
@Service("activationServiceV2")
public class ActivationService {

    private PowerAuthClient powerAuthClient;

    private static final Logger logger = LoggerFactory.getLogger(ActivationService.class);

    /**
     * Set PowerAuth service client via setter injection.
     * @param powerAuthClient PowerAuth service client.
     */
    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Create activation.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws PowerAuthActivationException In case create activation fails.
     */
    public ActivationCreateResponse createActivation(ActivationCreateRequest request) throws PowerAuthActivationException {
        try {
            final String activationIDShort = request.getActivationIdShort();
            final String activationNonce = request.getActivationNonce();
            final String cDevicePublicKey = request.getEncryptedDevicePublicKey();
            final String activationName = request.getActivationName();
            final String extras = request.getExtras();
            final String applicationKey = request.getApplicationKey();
            final String applicationSignature = request.getApplicationSignature();
            final String clientEphemeralKey = request.getEphemeralPublicKey();

            final PrepareActivationResponse paResponse = powerAuthClient.v2().prepareActivation(
                    activationIDShort,
                    activationName,
                    activationNonce,
                    clientEphemeralKey,
                    cDevicePublicKey,
                    extras,
                    applicationKey,
                    applicationSignature
            );

            final ActivationCreateResponse response = new ActivationCreateResponse();
            response.setActivationId(paResponse.getActivationId());
            response.setActivationNonce(paResponse.getActivationNonce());
            response.setEncryptedServerPublicKey(paResponse.getEncryptedServerPublicKey());
            response.setEncryptedServerPublicKeySignature(paResponse.getEncryptedServerPublicKeySignature());
            response.setEphemeralPublicKey(paResponse.getEphemeralPublicKey());

            return response;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }
    }

}
