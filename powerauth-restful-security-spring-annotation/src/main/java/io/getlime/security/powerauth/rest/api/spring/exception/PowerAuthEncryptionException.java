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
package io.getlime.security.powerauth.rest.api.spring.exception;

/**
 * Exception raised in case encryption or decryption fails.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthEncryptionException extends Exception {

    private static final long serialVersionUID = -4247463135868495185L;

    private static final String DEFAULT_CODE = "ERR_ENCRYPTION";
    private static final String DEFAULT_ERROR = "POWER_AUTH_ENCRYPTION_FAILED";

    /**
     * Default constructor
     */
    public PowerAuthEncryptionException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message
     * @param message Error message
     */
    public PowerAuthEncryptionException(String message) {
        super(message);
    }

    /**
     * Constructor with a cause.
     * @param cause Error cause.
     */
    public PowerAuthEncryptionException(Throwable cause) {
        super(cause);
    }

    /**
     * Get the default error code, used for example in REST response.
     * @return Default error code.
     */
    public String getDefaultCode() {
        return DEFAULT_CODE;
    }

    /**
     * Get default error message, used for example in the REST response.
     * @return Default error message.
     */
    public String getDefaultError() {
        return DEFAULT_ERROR;
    }

}
