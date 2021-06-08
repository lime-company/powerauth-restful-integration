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
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.rest.api.spring.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.converter.v3.ActivationContextConverter;
import io.getlime.security.powerauth.rest.api.spring.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.model.ActivationContext;
import io.getlime.security.powerauth.rest.api.spring.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

/**
 * Service implementing activation functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("activationServiceV3")
public class ActivationService {

    private PowerAuthClient powerAuthClient;

    private PowerAuthApplicationConfiguration applicationConfiguration;

    private CustomActivationProvider activationProvider;

    private ActivationContextConverter activationContextConverter;

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
     * Set application configuration class via setter injection.
     * @param applicationConfiguration Application configuration.
     */
    @Autowired(required = false)
    public void setApplicationConfiguration(PowerAuthApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    /**
     * Set PowerAuth activation provider via setter injection.
     * @param activationProvider PowerAuth activation provider.
     */
    @Autowired(required = false)
    public void setPowerAuthActivationProvider(CustomActivationProvider activationProvider) {
        this.activationProvider = activationProvider;
    }

    /**
     * Set activation context converter via setter injection.
     * @param activationContextConverter Activation context converter.
     */
    @Autowired
    public void setActivationContextConverter(ActivationContextConverter activationContextConverter) {
        this.activationContextConverter = activationContextConverter;
    }

    /**
     * Create activation.
     *
     * @param request Create activation layer 1 request.
     * @param eciesContext PowerAuth ECIES encryption context.
     * @return Create activation layer 1 response.
     * @throws PowerAuthActivationException In case create activation fails.
     * @throws PowerAuthRecoveryException In case activation recovery fails.
     */
    public ActivationLayer1Response createActivation(ActivationLayer1Request request, EciesEncryptionContext eciesContext) throws PowerAuthActivationException, PowerAuthRecoveryException {
        try {

            final String applicationKey = eciesContext.getApplicationKey();
            final EciesEncryptedRequest activationData = request.getActivationData();
            final String ephemeralPublicKey = activationData.getEphemeralPublicKey();
            final String encryptedData = activationData.getEncryptedData();
            final String mac = activationData.getMac();
            final String nonce = activationData.getNonce();
            final Map<String, String> identity = request.getIdentityAttributes();
            final Map<String, Object> customAttributes = (request.getCustomAttributes() != null) ? request.getCustomAttributes() : new HashMap<>();

            // Validate inner encryption
            if (nonce == null && !"3.0".equals(eciesContext.getVersion())) {
                logger.warn("Missing nonce for protocol version: {}", eciesContext.getVersion());
                throw new PowerAuthActivationException();
            }

            switch (request.getType()) {
                // Regular activation which uses "code" identity attribute
                case CODE: {

                    // Check if identity attributes are present
                    if (identity == null || identity.isEmpty()) {
                        logger.warn("Identity attributes are missing for code activation");
                        throw new PowerAuthActivationException();
                    }

                    // Extract data from request and encryption object
                    final String activationCode = identity.get("code");

                    if (activationCode == null || activationCode.isEmpty()) {
                        logger.warn("Activation code is missing");
                        throw new PowerAuthActivationException();
                    }

                    // Call PrepareActivation method on PA server
                    final PrepareActivationResponse response = powerAuthClient.prepareActivation(activationCode, applicationKey, ephemeralPublicKey, encryptedData, mac, nonce);

                    // Create context for passing parameters between activation provider calls
                    final Map<String, Object> context = new LinkedHashMap<>();

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes and save any flags
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE, context);
                        List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE, context);
                        if (activationFlags != null && !activationFlags.isEmpty()) {
                            powerAuthClient.addActivationFlags(response.getActivationId(), activationFlags);
                        }
                    }

                    boolean notifyActivationCommit = false;
                    if (response.getActivationStatus() == ActivationStatus.ACTIVE) {
                        // Activation was committed instantly due to presence of Activation OTP.
                        notifyActivationCommit = true;
                    } else {
                        // Otherwise check if activation should be committed instantly and if yes, perform commit.
                        if (activationProvider != null && activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE, context)) {
                            CommitActivationResponse commitResponse = powerAuthClient.commitActivation(response.getActivationId(), null);
                            notifyActivationCommit = commitResponse.isActivated();
                        }
                    }
                    // Notify activation provider about an activation commit.
                    if (activationProvider != null && notifyActivationCommit) {
                        activationProvider.activationWasCommitted(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE, context);
                    }

                    // Prepare and return encrypted response
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes);
                }

                // Custom activation
                case CUSTOM: {
                    // Check if there is a custom activation provider available, return an error in case it is not available
                    if (activationProvider == null) {
                        logger.warn("Activation provider is not available");
                        throw new PowerAuthActivationException();
                    }

                    // Check if identity attributes are present
                    if (identity == null || identity.isEmpty()) {
                        logger.warn("Identity attributes are missing for custom activation");
                        throw new PowerAuthActivationException();
                    }

                    // Create context for passing parameters between activation provider calls
                    final Map<String, Object> context = new LinkedHashMap<>();

                    // Lookup user ID using a provided identity attributes
                    final String userId = activationProvider.lookupUserIdForAttributes(identity, context);

                    // If no user was found or user ID is invalid, return an error
                    if (userId == null || userId.equals("") || userId.length() > 255) {
                        logger.warn("Invalid user ID: {}", userId);
                        throw new PowerAuthActivationException();
                    }

                    // Resolve maxFailedCount and activationExpireTimestamp parameters, null value means use value configured on PowerAuth server
                    final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, userId, ActivationType.CUSTOM, context);
                    final Long maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                    final Long activationValidityPeriod = activationProvider.getValidityPeriodDuringActivation(identity, customAttributes, userId, ActivationType.CUSTOM, context);
                    Date activationExpireTimestamp = null;
                    if (activationValidityPeriod != null) {
                        Instant now = Instant.now();
                        Instant expiration = now.plusMillis(activationValidityPeriod);
                        activationExpireTimestamp = Date.from(expiration);
                    }

                    // Create activation for a looked up user and application related to the given application key
                    final CreateActivationResponse response = powerAuthClient.createActivation(
                            userId,
                            activationExpireTimestamp,
                            maxFailedCount,
                            applicationKey,
                            ephemeralPublicKey,
                            encryptedData,
                            mac,
                            nonce
                    );

                    // Process custom attributes using a custom logic
                    final Map<String, Object> processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM, context);

                    // Save activation flags in case the provider specified any flags
                    final List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM, context);
                    if (activationFlags != null && !activationFlags.isEmpty()) {
                        powerAuthClient.addActivationFlags(response.getActivationId(), activationFlags);
                    }

                    // Check if activation should be committed instantly and if yes, perform commit
                    if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM, context)) {
                        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(response.getActivationId(), null);
                        if (commitResponse.isActivated()) {
                            activationProvider.activationWasCommitted(identity, customAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM, context);
                        }
                    }

                    // Prepare encrypted activation data
                    final EciesEncryptedResponse encryptedActivationData = new EciesEncryptedResponse(response.getEncryptedData(), response.getMac());

                    // Prepare the created activation response data
                    final ActivationLayer1Response responseL1 = new ActivationLayer1Response();
                    responseL1.setCustomAttributes(processedCustomAttributes);
                    responseL1.setActivationData(encryptedActivationData);

                    // Return response
                    return responseL1;
                }

                // Activation using recovery code
                case RECOVERY: {

                    // Check if identity attributes are present
                    if (identity == null || identity.isEmpty()) {
                        logger.warn("Identity attributes are missing for activation recovery");
                        throw new PowerAuthActivationException();
                    }

                    // Extract data from request and encryption object
                    final String recoveryCode = identity.get("recoveryCode");
                    final String recoveryPuk = identity.get("puk");

                    if (recoveryCode == null || recoveryCode.isEmpty()) {
                        logger.warn("Recovery code is missing");
                        throw new PowerAuthActivationException();
                    }

                    if (recoveryPuk == null || recoveryPuk.isEmpty()) {
                        logger.warn("Recovery PUK is missing");
                        throw new PowerAuthActivationException();
                    }

                    // Create context for passing parameters between activation provider calls
                    final Map<String, Object> context = new LinkedHashMap<>();

                    // Resolve maxFailedCount, user ID is not known
                    Long maxFailedCount = null;
                    if (activationProvider != null) {
                        final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, null, ActivationType.RECOVERY, context);
                        maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                    }

                    // Call RecoveryCodeActivation method on PA server
                    final RecoveryCodeActivationResponse response = powerAuthClient.createActivationUsingRecoveryCode(recoveryCode, recoveryPuk, applicationKey, maxFailedCount, ephemeralPublicKey, encryptedData, mac, nonce);

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes and save any flags
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY, context);
                        final List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY, context);
                        if (activationFlags != null && !activationFlags.isEmpty()) {
                            powerAuthClient.addActivationFlags(response.getActivationId(), activationFlags);
                        }
                    }

                    // Automatically commit activation by default, the optional activation provider can override automatic commit
                    if (activationProvider == null || activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY, context)) {
                        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(response.getActivationId(), null);
                        if (activationProvider != null && commitResponse.isActivated()) {
                            activationProvider.activationWasCommitted(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY, context);
                        }
                    }

                    // Prepare and return encrypted response
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes);
                }

                default:
                    logger.warn("Invalid activation request");
                    throw new PowerAuthInvalidRequestException();
            }
        } catch (PowerAuthClientException ex) {
            if (ex.getPowerAuthError() instanceof PowerAuthErrorRecovery) {
                final PowerAuthErrorRecovery errorRecovery = (PowerAuthErrorRecovery) ex.getPowerAuthError();
                logger.debug("Invalid recovery code, current PUK index: {}", errorRecovery.getCurrentRecoveryPukIndex());
                throw new PowerAuthRecoveryException(ex.getMessage(), "INVALID_RECOVERY_CODE", errorRecovery.getCurrentRecoveryPukIndex());
            }
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        } catch (PowerAuthActivationException ex) {
            // Do not swallow PowerAuthActivationException for custom activations.
            // See: https://github.com/wultra/powerauth-restful-integration/issues/199
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     *
     * @param request Activation status request.
     * @return Activation status response.
     * @throws PowerAuthActivationException In case retrieving activation status fails.
     */
    public ActivationStatusResponse getActivationStatus(ActivationStatusRequest request) throws PowerAuthActivationException {
        try {
            final String activationId = request.getActivationId();
            final String challenge = request.getChallenge();
            final GetActivationStatusResponse paResponse = powerAuthClient.getActivationStatusWithEncryptedStatusBlob(activationId, challenge);
            final ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(paResponse.getActivationId());
            response.setEncryptedStatusBlob(paResponse.getEncryptedStatusBlob());
            response.setNonce(paResponse.getEncryptedStatusBlobNonce());
            if (applicationConfiguration != null) {
                final ActivationContext activationContext = activationContextConverter.fromActivationDetailResponse(paResponse);
                response.setCustomObject(applicationConfiguration.statusServiceCustomObject(activationContext));
            }
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation status check failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Remove activation.
     *
     * @param apiAuthentication PowerAuth API authentication object.
     * @return Activation remove response.
     * @throws PowerAuthActivationException     In case remove activation fails.
     */
    public ActivationRemoveResponse removeActivation(PowerAuthApiAuthentication apiAuthentication) throws PowerAuthActivationException {
        try {

            // Fetch context information
            final String activationId = apiAuthentication.getActivationId();
            final String userId = apiAuthentication.getUserId();
            final Long applicationId = apiAuthentication.getApplicationId();

            // Call other application specific cleanup logic
            final RemoveActivationResponse paResponse;
            if (activationProvider != null) {
                final boolean revokeCodes = activationProvider.shouldRevokeRecoveryCodeOnRemove(activationId, userId, applicationId);
                paResponse = powerAuthClient.removeActivation(activationId, null, revokeCodes);
                activationProvider.activationWasRemoved(activationId, userId, applicationId);
            } else {
                paResponse = powerAuthClient.removeActivation(activationId, null); // do not revoke recovery codes
            }

            // Prepare and return the response
            final ActivationRemoveResponse response = new ActivationRemoveResponse();
            response.setActivationId(paResponse.getActivationId());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation removal failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Prepare payload for the encrypted response.
     *
     * @param encryptedData Encrypted data.
     * @param mac MAC code of the encrypted data.
     * @param processedCustomAttributes Custom attributes to be returned.
     * @return Encrypted response object.
     */
    private ActivationLayer1Response prepareEncryptedResponse(String encryptedData, String mac, Map<String, Object> processedCustomAttributes) {
        // Prepare encrypted response object for layer 2
        final EciesEncryptedResponse encryptedResponseL2 = new EciesEncryptedResponse();
        encryptedResponseL2.setEncryptedData(encryptedData);
        encryptedResponseL2.setMac(mac);

        // The response is encrypted once more before sent to client using ResponseBodyAdvice
        final ActivationLayer1Response responseL1 = new ActivationLayer1Response();
        responseL1.setCustomAttributes(processedCustomAttributes);
        responseL1.setActivationData(encryptedResponseL2);
        return responseL1;
    }

}
