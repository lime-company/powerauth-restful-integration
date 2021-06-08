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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.v3.GetEciesDecryptorResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesDecryptorParameters;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Implementation of PowerAuth encryption provider.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Component
public class PowerAuthEncryptionProvider extends PowerAuthEncryptionProviderBase  {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthEncryptionProvider.class);

    private PowerAuthClient powerAuthClient;

    /**
     * Set PowerAuth client via setter injection.
     *
     * @param powerAuthClient PowerAuth client.
     */
    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Override
    public PowerAuthEciesDecryptorParameters getEciesDecryptorParameters(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthEncryptionException {
        try {
            GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
            eciesDecryptorRequest.setActivationId(activationId);
            eciesDecryptorRequest.setApplicationKey(applicationKey);
            eciesDecryptorRequest.setEphemeralPublicKey(ephemeralPublicKey);
            GetEciesDecryptorResponse eciesDecryptorResponse = powerAuthClient.getEciesDecryptor(eciesDecryptorRequest);
            return new PowerAuthEciesDecryptorParameters(eciesDecryptorResponse.getSecretKey(), eciesDecryptorResponse.getSharedInfo2());
        } catch (Exception ex) {
            logger.warn("Get ECIES decryptor call failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
    }

}
