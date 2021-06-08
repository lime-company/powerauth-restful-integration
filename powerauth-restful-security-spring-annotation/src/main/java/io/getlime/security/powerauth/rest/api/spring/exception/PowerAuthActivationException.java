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
 * Exception related to processes during a new activation process.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthActivationException extends Exception {

    private static final long serialVersionUID = -7975115359211508795L;

    private static final String DEFAULT_CODE = "ERR_ACTIVATION";
    private static final String DEFAULT_ERROR = "POWER_AUTH_ACTIVATION_INVALID";

    /**
     * Default constructor.
     */
    public PowerAuthActivationException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message.
     * @param message Error message.
     */
    public PowerAuthActivationException(String message) {
        super(message);
    }

    /**
     * Constructor with a cause.
     * @param cause Error cause.
     */
    public PowerAuthActivationException(Throwable cause) {
        super(cause);
    }

    /**
     * Get default error code, used for example in the REST response.
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
