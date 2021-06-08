/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2020 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.exception.authentication;

import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;

/**
 * Exception raised in case PowerAuth token validation fails.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthTokenInvalidException extends PowerAuthAuthenticationException {

    private static final long serialVersionUID = 1052831183125328518L;

    private static final String DEFAULT_CODE = "ERR_AUTHENTICATION";
    private static final String DEFAULT_ERROR = "POWER_AUTH_TOKEN_INVALID";

    /**
     * Default constructor
     */
    public PowerAuthTokenInvalidException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message
     * @param message Error message
     */
    public PowerAuthTokenInvalidException(String message) {
        super(message);
    }

    /**
     * Constructor with a cause.
     * @param cause Error cause.
     */
    public PowerAuthTokenInvalidException(Throwable cause) {
        super(cause);
    }

    /**
     * Get the default error code, used for example in REST response.
     * @return Default error code.
     */
    public String getDefaultCode() {
        return DEFAULT_CODE;
    }
}
