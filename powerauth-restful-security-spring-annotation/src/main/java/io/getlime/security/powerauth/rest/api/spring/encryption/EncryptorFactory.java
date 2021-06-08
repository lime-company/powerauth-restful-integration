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
package io.getlime.security.powerauth.rest.api.spring.encryption;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v2.GetNonPersonalizedEncryptionKeyResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Class responsible for building encryptors.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class EncryptorFactory {

    private static final Logger logger = LoggerFactory.getLogger(EncryptorFactory.class);
    private PowerAuthClient powerAuthClient;

    /**
     * Default constructor.
     */
    public EncryptorFactory() {
    }

    /**
     * Set PowerAuth client via the setter injection.
     * @param powerAuthClient PowerAuth client.
     */
    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Return a new instance of a non-personalized encryptor.
     * @param object Request object to be used to initialize a new encryptor.
     * @return New instance of a non-personalized encryptor.
     * @throws PowerAuthEncryptionException Thrown in case encryptor could not be built.
     */
    public PowerAuthNonPersonalizedEncryptor buildNonPersonalizedEncryptor(ObjectRequest<NonPersonalizedEncryptedPayloadModel> object) throws PowerAuthEncryptionException {
        return this.buildNonPersonalizedEncryptor(
                object.getRequestObject().getApplicationKey(),
                object.getRequestObject().getSessionIndex(),
                object.getRequestObject().getEphemeralPublicKey()
        );
    }

    /**
     * Return a new instance of a non-personalized encryptor.
     * @param applicationKeyBase64 Application key associated with an application master key used for encryption.
     * @param sessionIndexBase64 Session index.
     * @param ephemeralPublicKeyBase64 Ephemeral public key.
     * @return New instance of a non-personalized encryptor.
     * @throws PowerAuthEncryptionException Thrown in case encryptor could not be built.
     */
    public PowerAuthNonPersonalizedEncryptor buildNonPersonalizedEncryptor(String applicationKeyBase64, String sessionIndexBase64, String ephemeralPublicKeyBase64) throws PowerAuthEncryptionException {
        try {
            final GetNonPersonalizedEncryptionKeyResponse encryptionKeyResponse = powerAuthClient.v2().generateNonPersonalizedE2EEncryptionKey(
                    applicationKeyBase64,
                    ephemeralPublicKeyBase64,
                    sessionIndexBase64
            );
            return new PowerAuthNonPersonalizedEncryptor(
                    encryptionKeyResponse.getApplicationKey(),
                    encryptionKeyResponse.getEncryptionKey(), encryptionKeyResponse.getEncryptionKeyIndex(),
                    encryptionKeyResponse.getEphemeralPublicKey()
            );
        } catch (PowerAuthClientException ex) {
            logger.warn("Encryption failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
    }

}
