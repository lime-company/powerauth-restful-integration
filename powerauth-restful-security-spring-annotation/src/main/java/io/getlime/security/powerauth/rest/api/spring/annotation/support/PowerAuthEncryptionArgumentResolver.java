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
package io.getlime.security.powerauth.rest.api.spring.annotation.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Argument resolver for {@link PowerAuthEciesEncryption} objects. It enables automatic
 * parameter resolution for methods that are annotated via {@link PowerAuthEciesEncryption} annotation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEncryptionArgumentResolver implements HandlerMethodArgumentResolver {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthEncryptionArgumentResolver.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supportsParameter(@NonNull MethodParameter parameter) {
        return parameter.hasMethodAnnotation(PowerAuthEncryption.class)
                && (parameter.hasParameterAnnotation(EncryptedRequestBody.class) || EciesEncryptionContext.class.isAssignableFrom(parameter.getParameterType()));
    }

    @Override
    public Object resolveArgument(@NonNull MethodParameter parameter, ModelAndViewContainer mavContainer, @NonNull NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        final HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        final PowerAuthEciesEncryption<?> eciesObject = (PowerAuthEciesEncryption<?>) request.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT);
        // Decrypted object is inserted into parameter annotated by @EncryptedRequestBody annotation
        if (parameter.hasParameterAnnotation(EncryptedRequestBody.class) && eciesObject != null && eciesObject.getDecryptedRequest() != null) {
            final Class<?> parameterType = parameter.getParameterType();
            if (parameterType.equals(byte[].class)) {
                return eciesObject.getDecryptedRequest();
            } else {
                try {
                    return objectMapper.readValue(eciesObject.getDecryptedRequest(), parameterType);
                } catch (IOException ex) {
                    logger.warn("Invalid request, error: {}", ex.getMessage());
                    logger.debug("Error details", ex);
                    return null;
                }
            }
        }
        // Ecies encryption object is inserted into parameter which is of type PowerAuthEciesEncryption
        if (eciesObject != null && EciesEncryptionContext.class.isAssignableFrom(parameter.getParameterType())) {
            // Set ECIES scope in case it is specified by the @PowerAuthEncryption annotation
            PowerAuthEncryption powerAuthEncryption = parameter.getMethodAnnotation(PowerAuthEncryption.class);
            if (powerAuthEncryption != null) {
                EciesEncryptionContext eciesContext = eciesObject.getContext();
                boolean validScope = validateEciesScope(eciesContext);
                if (validScope) {
                    return eciesContext;
                }
            }
        }
        return null;
    }

    /**
     * Validate that encryption HTTP header contains correct values for given ECIES scope.
     * @param eciesContext ECIES context.
     */
    private boolean validateEciesScope(EciesEncryptionContext eciesContext) {
        switch (eciesContext.getEciesScope()) {
            case ACTIVATION_SCOPE:
                if (eciesContext.getApplicationKey() == null || eciesContext.getApplicationKey().isEmpty()) {
                    logger.warn("ECIES activation scope is invalid because of missing application key");
                    return false;
                }
                if (eciesContext.getActivationId() == null || eciesContext.getActivationId().isEmpty()) {
                    logger.warn("ECIES activation scope is invalid because of missing activation ID");
                    return false;
                }
                break;

            case APPLICATION_SCOPE:
                if (eciesContext.getApplicationKey() == null || eciesContext.getApplicationKey().isEmpty()) {
                    logger.warn("ECIES application scope is invalid because of missing application key");
                    return false;
                }
                break;

            default:
                logger.warn("Unsupported ECIES scope: {}", eciesContext.getEciesScope());
                return false;
        }
        return true;
    }

}
