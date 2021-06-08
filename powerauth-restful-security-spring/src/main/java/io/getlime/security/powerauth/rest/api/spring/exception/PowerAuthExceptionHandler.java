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

import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.rest.api.model.exception.RecoveryErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Implementation of a PA2.0 Standard RESTful API exception handler.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@ControllerAdvice
@Order(PowerAuthExceptionHandler.PRECEDENCE)
public class PowerAuthExceptionHandler {

    /**
     * Precedence value that makes sure to apply the filters in the right order.
     */
    public static final int PRECEDENCE = -100;

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthExceptionHandler.class);

    /**
     * Handle PowerAuthAuthenticationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthAuthenticationException.class)
    @ResponseStatus(value = HttpStatus.UNAUTHORIZED)
    public @ResponseBody ErrorResponse handleUnauthorizedException(PowerAuthAuthenticationException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthActivationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthActivationException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleActivationException(PowerAuthActivationException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }


    /**
     * Handle PowerAuthRecoveryException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthRecoveryException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody RecoveryErrorResponse handleRecoveryException(PowerAuthRecoveryException ex) {
        logger.warn(ex.getMessage(), ex);
        return new RecoveryErrorResponse(ex.getErrorCode(), ex.getDefaultError(), ex.getCurrentRecoveryPukIndex());
    }

    /**
     * Handle PowerAuthSecureVaultException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthSecureVaultException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleSecureVaultException(PowerAuthSecureVaultException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthEncryptionException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthEncryptionException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthEncryptionException(PowerAuthEncryptionException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthUpgradeException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthUpgradeException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthUpgradeException(PowerAuthUpgradeException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

}
