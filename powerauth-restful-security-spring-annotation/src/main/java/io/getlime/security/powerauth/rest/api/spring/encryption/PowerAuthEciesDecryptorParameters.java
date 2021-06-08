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

/**
 * Class used for storing ECIES decryptor parameters.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEciesDecryptorParameters {

    private final String secretKey;
    private final String sharedInfo2;

    /**
     * Constructor with secretKey and sharedInfo2.
     *
     * @param secretKey ECIES secret key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     */
    public PowerAuthEciesDecryptorParameters(String secretKey, String sharedInfo2) {
        this.secretKey = secretKey;
        this.sharedInfo2 = sharedInfo2;
    }

    /**
     * Get ECIES secret key.
     *
     * @return ECIES secret key.
     */
    public String getSecretKey() {
        return secretKey;
    }

    /**
     * Get parameter sharedInfo2 for ECIES.
     * @return Parameter sharedInfo2 for ECIES.
     */
    public String getSharedInfo2() {
        return sharedInfo2;
    }

}
