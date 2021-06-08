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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthToken;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthEncryptionProvider;
import org.apache.commons.text.StringSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Interceptor class for the PowerAuth related annotations: @PowerAuth, @PowerAuthToken and @PowerAuthEncryption.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class PowerAuthAnnotationInterceptor implements AsyncHandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAnnotationInterceptor.class);

    private PowerAuthAuthenticationProvider authenticationProvider;
    private PowerAuthEncryptionProvider encryptionProvider;

    /**
     * Set authentication provider via setter injection.
     * @param authenticationProvider Authentication provider.
     */
    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    /**
     * Set encryption provider via setter injection.
     * @param encryptionProvider Encryption provider.
     */
    @Autowired
    public void setEncryptionProvider(PowerAuthEncryptionProvider encryptionProvider) {
        this.encryptionProvider = encryptionProvider;
    }

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Object handler) {

        // Check if the provided handler is related to handler method.
        // This is to avoid issues with possible CORS requests )in case of
        // incorrect filter mapping) where there are special "pre-flight"
        // requests before the actual requests.
        if (handler instanceof HandlerMethod) {

            final HandlerMethod handlerMethod = (HandlerMethod) handler;

            // Obtain annotations
            PowerAuth powerAuthSignatureAnnotation = handlerMethod.getMethodAnnotation(PowerAuth.class);
            PowerAuthToken powerAuthTokenAnnotation = handlerMethod.getMethodAnnotation(PowerAuthToken.class);
            PowerAuthEncryption powerAuthEncryptionAnnotation = handlerMethod.getMethodAnnotation(PowerAuthEncryption.class);

            // Check that either signature or token annotation is active
            if (powerAuthSignatureAnnotation != null && powerAuthTokenAnnotation != null) {
                logger.warn("You cannot use both @PowerAuth and @PowerAuthToken on same handler method. We are removing both.");
                powerAuthSignatureAnnotation = null;
                powerAuthTokenAnnotation = null;
            }

            // Resolve @PowerAuthEncryption annotation. The order of processing is important, PowerAuth expects
            // sign-then-encrypt sequence in case both authorization and encryption are used.
            if (powerAuthEncryptionAnnotation != null) {
                final Class<?> requestType = resolveGenericParameterTypeForEcies(handlerMethod);
                try {
                    encryptionProvider.decryptRequest(request, requestType, powerAuthEncryptionAnnotation.scope());
                    // Encryption object is saved in HTTP servlet request by encryption provider, so that it is available for both Spring and Java EE
                } catch (PowerAuthEncryptionException ex) {
                    logger.warn("Decryption failed, error: {}", ex.getMessage());
                    logger.debug("Error details", ex);
                }
            }

            // Resolve @PowerAuth annotation
            if (powerAuthSignatureAnnotation != null) {
                try {
                    final String resourceId = expandResourceId(powerAuthSignatureAnnotation.resourceId(), request, handlerMethod);
                    final String header = request.getHeader(PowerAuthSignatureHttpHeader.HEADER_NAME);
                    final List<PowerAuthSignatureTypes> signatureTypes = Arrays.asList(powerAuthSignatureAnnotation.signatureType());
                    final PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature(
                            request, resourceId, header, signatureTypes
                    );
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, authentication);
                } catch (PowerAuthAuthenticationException ex) {
                    logger.warn("Invalid request signature, authentication object was removed");
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, null);
                }
            }

            // Resolve @PowerAuthToken annotation
            if (powerAuthTokenAnnotation != null) {
                try {
                    final String header = request.getHeader(PowerAuthTokenHttpHeader.HEADER_NAME);
                    final List<PowerAuthSignatureTypes> signatureTypes = Arrays.asList(powerAuthTokenAnnotation.signatureType());
                    final PowerAuthApiAuthentication authentication = authenticationProvider.validateToken(
                            header, signatureTypes
                    );
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, authentication);
                } catch (PowerAuthAuthenticationException ex) {
                    logger.warn("Invalid token, authentication object was removed");
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, null);
                }
            }

        }

        return true;
    }

    /**
     * Resolve type of request object which is annotated by the @EncryptedRequestBody annotation.
     * In case such parameter is missing the Object.class type is returned.
     *
     * @param handlerMethod Handler method.
     * @return Resolved type of request object.
     */
    private Class<?> resolveGenericParameterTypeForEcies(HandlerMethod handlerMethod) {
        for (MethodParameter parameter: handlerMethod.getMethodParameters()) {
            if (parameter.hasParameterAnnotation(EncryptedRequestBody.class)) {
                return parameter.getParameterType();
            }
        }
        return Object.class;
    }

    /**
     * The method substitutes placeholders (marked via "${placeholder}") in resourceID attribute value by
     * the actual parameters of the handler method. The implementation takes into account all method parameters
     * that are annotated via @RequestParam or @PathVariable annotations and extracts values from the request
     * parameter map.<br>
     * <br>
     * <b>
     *     Note: In case both @RequestParam and @PathVariable with the same name exist, the value of @RequestParam
     *     takes precedence. This is because @RequestParam usually maps to the HTTP GET query parameter that cannot
     *     be easily changed in existing API, while @PathVariable is just a URL placeholder that can be renamed in
     *     the code with no impact on functionality.
     * </b>
     *
     * @param resourceId Resource ID with possible placeholders.
     * @param request HttpServletRequest for the current execution.
     * @param handlerMethod Handler method that is responsible for the request processing.
     * @return Resource ID with substituted placeholders.
     */
    @SuppressWarnings("unchecked")
    private String expandResourceId(String resourceId, HttpServletRequest request, HandlerMethod handlerMethod) {
        // Get method parameters that could be replaced in the context of resource ID
        final Map<String, String> parameters = new TreeMap<>();
        final MethodParameter[] methodParameters = handlerMethod.getMethodParameters();
        for (MethodParameter mp : methodParameters) {
            // Handle parameters annotated by @RequestParam annotation.
            // These are stored in the servlet request parameter map.
            // Note: @RequestParam must be processed before @PathVariable since
            //       in API, it cannot be renamed (the path variable is just
            //       a placeholder and can have arbitrary name).
            final RequestParam requestParam = mp.getParameterAnnotation(RequestParam.class);
            if (requestParam != null) {
                final String name = requestParam.name();
                final String value = request.getParameter(name);
                if (value != null) { // do not check "&& !parameters.containsKey(name)" because in the case of
                                     // a name conflict, we want @RequestParam to overwrite @PathVariable value
                    parameters.put(name, value);
                }
            } else {
                // Handle parameters annotated by @PathVariable annotation.
                // These are stored by Spring in the servlet request attributes map, under a special
                // URI_TEMPLATE_VARIABLES_ATTRIBUTE key that contains Map<String, String> with path
                // variable mapping.
                final PathVariable pathVariable = mp.getParameterAnnotation(PathVariable.class);
                if (pathVariable != null) {
                    final String name = pathVariable.name();
                    final Map<String, String> pathVariableMap = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
                    if (pathVariableMap != null && !parameters.containsKey(name)) { // prevent overwriting value that is already assigned
                        final String value = pathVariableMap.get(name);
                        if (value != null) {
                            parameters.put(name, value);
                        }
                    }
                }
            }
        }
        // Substitute the placeholders
        final StringSubstitutor sub = new StringSubstitutor(parameters);
        return sub.replace(resourceId);
    }

}
