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
package io.getlime.security.powerauth.app.rest.api.spring.controller.v2;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v2.CreateActivationResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sample controller for a custom activation implementation.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("customActivationControllerV2")
@RequestMapping(value = "/pa/activation/direct")
public class CustomActivationController {

    private static final Logger logger = LoggerFactory.getLogger(CustomActivationController.class);

    private PowerAuthClient powerAuthClient;

    private EncryptorFactory encryptorFactory;

    private CustomActivationProvider activationProvider;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setEncryptorFactory(EncryptorFactory encryptorFactory) {
        this.encryptorFactory = encryptorFactory;
    }

    @Autowired(required = false)
    public void setPowerAuthActivationProvider(CustomActivationProvider activationProvider) {
        this.activationProvider = activationProvider;
    }

    /**
     * Sample custom activation implementation for version 2 of activations.
     *
     * @param encryptedRequest Activation request encrypted using non-personalised end-to-end encryption.
     * @return Encrypted activation response.
     * @throws PowerAuthActivationException In case custom activation fails.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> createActivationV2(
            @RequestBody ObjectRequest<NonPersonalizedEncryptedPayloadModel> encryptedRequest
    ) throws PowerAuthActivationException {
        try {

            // Check if there is any user provider to be autowired
            if (activationProvider == null) {
                logger.warn("Activation provider is missing");
                throw new PowerAuthActivationException();
            }

            // Prepare an encryptor
            final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(encryptedRequest);
            if (encryptor == null) {
                logger.warn("Encryptor is not available");
                throw new PowerAuthActivationException();
            }

            // Decrypt the request object
            ActivationCreateCustomRequest request = encryptor.decrypt(encryptedRequest, ActivationCreateCustomRequest.class);

            if (request == null) {
                logger.warn("Invalid request in activation create");
                throw new PowerAuthActivationException();
            }

            // Create context for passing parameters between activation provider calls
            Map<String, Object> context = new LinkedHashMap<>();

            // Lookup user ID using a provided identity
            final Map<String, String> identity = request.getIdentity();
            String userId = activationProvider.lookupUserIdForAttributes(identity, context);

            // If no user was found or user ID is invalid, return error
            if (userId == null || userId.equals("") || userId.length() > 255) {
                logger.warn("User ID is invalid: {}", userId);
                throw new PowerAuthActivationException();
            }

            // Create activation for a looked up user and application related to the given application key
            ActivationCreateRequest acr = request.getPowerauth();
            CreateActivationResponse response = powerAuthClient.v2().createActivation(
                    acr.getApplicationKey(),
                    userId,
                    acr.getActivationIdShort(),
                    acr.getActivationName(),
                    acr.getActivationNonce(),
                    acr.getEphemeralPublicKey(),
                    acr.getEncryptedDevicePublicKey(),
                    acr.getExtras(),
                    acr.getApplicationSignature()
            );

            // Process custom attributes using a custom logic
            final Map<String, Object> customAttributes = request.getCustomAttributes();
            activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, null, ActivationType.CUSTOM, context);

            // Prepare the created activation response data
            ActivationCreateResponse createResponse = new ActivationCreateResponse();
            createResponse.setActivationId(response.getActivationId());
            createResponse.setEphemeralPublicKey(response.getEphemeralPublicKey());
            createResponse.setActivationNonce(response.getActivationNonce());
            createResponse.setEncryptedServerPublicKey(response.getEncryptedServerPublicKey());
            createResponse.setEncryptedServerPublicKeySignature(response.getEncryptedServerPublicKeySignature());

            // Encrypt response object
            final ObjectResponse<NonPersonalizedEncryptedPayloadModel> powerAuthApiResponse = encryptor.encrypt(createResponse);

            // Check if activation should be committed instantly and if yes, perform commit
            if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), userId, null, ActivationType.CUSTOM, context)) {
                powerAuthClient.commitActivation(response.getActivationId(), null);
            }

            // Return response
            return powerAuthApiResponse;

        } catch (Exception ex) {
            logger.warn("Create activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }

    }
}
