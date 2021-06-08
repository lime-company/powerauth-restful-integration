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

import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Interface which enables implementation of custom activations. The interface defines a method for obtaining
 * a user ID based on arbitrary identity attributes, processing of custom activation attributes and configuration
 * of auto-commit mode.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface CustomActivationProvider {

    /**
     * This method is responsible for looking user ID up based on a provided set of identity attributes.
     * <br><br>
     * This method is called for the CUSTOM activation type only.
     *
     * @param identityAttributes Attributes that uniquely identify user with given ID.
     * @param context Context for passing parameters between activation provider calls.
     * @return User ID value.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    String lookupUserIdForAttributes(Map<String, String> identityAttributes, Map<String, Object> context) throws PowerAuthActivationException;

    /**
     * Process custom attributes, in any way that is suitable for the purpose of your application.
     * <br><br>
     * This method is called for all activation types. Default implementation returns unmodified attributes.
     *
     * @param customAttributes Custom attributes (not related to identity) to be processed.
     * @param activationId Activation ID of created activation.
     * @param userId User ID of user who created the activation.
     * @param appId Application ID of the application associated to the activation.
     * @param activationType Activation type.
     * @param context Context for passing parameters between activation provider calls.
     * @return Custom attributes after processing.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    default Map<String, Object> processCustomActivationAttributes(Map<String, Object> customAttributes, String activationId, String userId, Long appId, ActivationType activationType, Map<String, Object> context) throws PowerAuthActivationException {
        return customAttributes;
    }

    /**
     * Variable that specifies if the activation should be automatically committed based on provided attributes.
     * Return true in case you would like to create an activation that is ready to be used for signing (ACTIVE),
     * and false for the cases when you need activation to remain in PENDING_COMMIT state.
     * <br><br>
     * Note that this setting only affects CUSTOM or RECOVERY activation types. On CODE activation type, auto-commit
     * is always disabled. Default implementation returns false.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param activationId Activation ID of created activation.
     * @param userId User ID of user who created the activation.
     * @param appId Application ID of the application associated to the activation.
     * @param activationType Activation type.
     * @param context Context for passing parameters between activation provider calls.
     * @return True in case activation should be committed, false otherwise.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    default boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, Long appId, ActivationType activationType, Map<String, Object> context) throws PowerAuthActivationException {
        return false;
    }

    /**
     * Method is called when activation commit succeeds.
     * <br><br>
     * Note that this method is only called for CUSTOM or RECOVERY activation types, and only in the case activation
     * was successfully committed on the server side. Method is not called in case commit fails on server. On CODE
     * activation type, auto-commit is always disabled and hence this method is not called. Default implementation
     * is no-op.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param activationId Activation ID of created activation.
     * @param userId User ID of user who created the activation.
     * @param appId Application ID of the application associated to the activation.
     * @param activationType Activation type.
     * @param context Context for passing parameters between activation provider calls.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    default void activationWasCommitted(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, Long appId, ActivationType activationType, Map<String, Object> context) throws PowerAuthActivationException {}

    /**
     * Method that indicates if the recovery codes should be revoked when an activation is removed.
     *
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param appId Application ID.
     * @return True in case the recovery codes should be revoked on remove, false otherwise.
     **/
    default boolean shouldRevokeRecoveryCodeOnRemove(String activationId, String userId, Long appId) {
        return false;
    }

    /**
     * Method is called after activation was just removed using the standard removal endpoint.
     * <br><br>
     * This method is called for all activations. Default implementation is no-op.
     *
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param appId Application ID.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    default void activationWasRemoved(String activationId, String userId, Long appId) throws PowerAuthActivationException {}

    /**
     * Get maximum failed attempt count for activations.
     * Use null value for using value which is configured on PowerAuth server.
     * <br><br>
     * Note that this method is only called for CUSTOM or RECOVERY activation types, since for CODE activation,
     * the number of max. failed attempts is set earlier while creating the activation code. Default implementation returns
     * null (use the server configured value).
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     * @param context Context for passing parameters between activation provider calls.
     * @return Maximum failed attempt count for activations.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    default Integer getMaxFailedAttemptCount(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String userId, ActivationType activationType, Map<String, Object> context) throws PowerAuthActivationException {
        return null;
    }

    /**
     * Get length of the period of activation record validity during activation in milliseconds.
     * Use null value for using value which is configured on PowerAuth server.
     * <br><br>
     * Note that this method is only called for CUSTOM or RECOVERY activation types, since for CODE activation,
     * the expiration period for activation is set earlier while creating the activation code. Default implementation returns
     * null (use the server configured value).
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     * @param context Context for passing parameters between activation provider calls.
     * @return Period in milliseconds during which activation is valid before it expires.
     * @throws PowerAuthActivationException In case of error in custom activation business logic that should terminate the rest of the activation.
     */
    default Long getValidityPeriodDuringActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String userId, ActivationType activationType, Map<String, Object> context) throws PowerAuthActivationException {
        return null;
    }

    /**
     * Get activation flags which should be saved for the created activation.
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param activationId Activation ID.
     * @param userId User ID of user who created the activation.
     * @param appId Application ID of the application associated to the activation.
     * @param activationType Activation type.
     * @param context Context for passing parameters between activation provider calls.
     * @return List of activation flags.
     */
    default List<String> getActivationFlags(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, Long appId, ActivationType activationType, Map<String, Object> context) {
        return Collections.emptyList();
    }

}
