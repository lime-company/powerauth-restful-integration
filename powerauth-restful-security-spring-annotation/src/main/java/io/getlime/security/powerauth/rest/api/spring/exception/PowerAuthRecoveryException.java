/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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
 * Exception thrown in case PowerAuth recovery fails, with optional current PUK index.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthRecoveryException extends Exception {

    private static final long serialVersionUID = 6497199187989286105L;

    private static final String DEFAULT_CODE = "ERR_RECOVERY";
    private static final String DEFAULT_ERROR = "POWER_AUTH_RECOVERY_INVALID";

    /**
     * Error code.
     */
    private String errorCode;

    /**
     * Index of the recovery PUK index.
     */
    private Integer currentRecoveryPukIndex;

    /**
     * Default constructor.
     */
    public PowerAuthRecoveryException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message.
     * @param message Error message.
     */
    public PowerAuthRecoveryException(String message) {
        super(message);
    }

    /**
     * Constructor with a custom error message and error code.
     * @param message Error message.
     * @param errorCode Error code.
     */
    public PowerAuthRecoveryException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructor with a custom error message, error code and current recovery PUK index.
     * @param message Error message.
     * @param errorCode Error code.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     */
    public PowerAuthRecoveryException(String message, String errorCode, Integer currentRecoveryPukIndex) {
        super(message);
        this.errorCode = errorCode;
        this.currentRecoveryPukIndex = currentRecoveryPukIndex;
    }

    /**
     * Get error code.
     * @return Error code.
     */
    public String getErrorCode() {
        if (errorCode == null) {
            return DEFAULT_CODE;
        }
        return errorCode;
    }

    /**
     * Get default error message, used for example in the REST response.
     * @return Default error message.
     */
    public String getDefaultError() {
        return DEFAULT_ERROR;
    }

    /**
     * Set error code.
     * @param errorCode Error code.
     */
    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * Get current recovery PUK index.
     * @return Current recovery PUK index.
     */
    public Integer getCurrentRecoveryPukIndex() {
        return currentRecoveryPukIndex;
    }

    /**
     * Set current recovery PUK index.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     */
    public void setCurrentRecoveryPukIndex(Integer currentRecoveryPukIndex) {
        this.currentRecoveryPukIndex = currentRecoveryPukIndex;
    }
}
