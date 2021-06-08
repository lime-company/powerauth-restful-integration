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
package io.getlime.security.powerauth.rest.api.spring.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Controller advice used for encryption of responses of REST endpoints.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ControllerAdvice
public class EncryptionResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionResponseBodyAdvice.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

    /**
     * Set request mapping handler adapter via setter injection. Note: Autowiring in constructor cannot be
     * used due to circular dependency.
     * @param requestMappingHandlerAdapter Request mapping handler adapter.
     */
    @Autowired
    public void setRequestMappingHandlerAdapter(RequestMappingHandlerAdapter requestMappingHandlerAdapter) {
        this.requestMappingHandlerAdapter = requestMappingHandlerAdapter;
    }

    /**
     * Whether method supports encryption. Standard implementation supports conversion to JSON, String or byte[].
     *
     * @param methodParameter Method parameter.
     * @param converterClass Chosen HTTP message converter class.
     * @return Whether method supports encryption.
     */
    @Override
    public boolean supports(@NonNull MethodParameter methodParameter, @NonNull Class<? extends HttpMessageConverter<?>> converterClass) {
        return methodParameter.hasMethodAnnotation(PowerAuthEncryption.class) &&
                (converterClass.isAssignableFrom(MappingJackson2HttpMessageConverter.class)
                        || converterClass.isAssignableFrom(StringHttpMessageConverter.class)
                        || converterClass.isAssignableFrom(ByteArrayHttpMessageConverter.class));
    }

    /**
     * Encrypt response before writing body.
     *
     * @param response Response object.
     * @param methodParameter Method parameter.
     * @param mediaType Selected HTTP response media type.
     * @param converterClass Selected HTTP message converter class.
     * @param serverHttpRequest HTTP request.
     * @param serverHttpResponse HTTP response.
     * @return ECIES cryptogram.
     */
    @Override
    public Object beforeBodyWrite(Object response, @NonNull MethodParameter methodParameter, @NonNull MediaType mediaType, @NonNull Class<? extends HttpMessageConverter<?>> converterClass, @NonNull ServerHttpRequest serverHttpRequest, @NonNull ServerHttpResponse serverHttpResponse) {
        if (response == null) {
            return null;
        }

        // Extract ECIES encryption object from HTTP request
        final HttpServletRequest httpServletRequest = ((ServletServerHttpRequest) serverHttpRequest).getServletRequest();
        final PowerAuthEciesEncryption<?> eciesEncryption = (PowerAuthEciesEncryption<?>) httpServletRequest.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT);
        if (eciesEncryption == null) {
            return null;
        }

        // Convert response to JSON
        try {
            byte[] responseBytes = serializeResponseObject(response);

            // Encrypt response using decryptor and return ECIES cryptogram
            final EciesDecryptor eciesDecryptor = eciesEncryption.getEciesDecryptor();
            final EciesCryptogram cryptogram = eciesDecryptor.encryptResponse(responseBytes);
            final String encryptedDataBase64 = BaseEncoding.base64().encode(cryptogram.getEncryptedData());
            final String macBase64 = BaseEncoding.base64().encode(cryptogram.getMac());

            // Return encrypted response with type given by converter class
            final EciesEncryptedResponse encryptedResponse = new EciesEncryptedResponse(encryptedDataBase64, macBase64);
            if (converterClass.isAssignableFrom(MappingJackson2HttpMessageConverter.class)) {
                // Object conversion is done automatically using MappingJackson2HttpMessageConverter
                return encryptedResponse;
            } else if (converterClass.isAssignableFrom(StringHttpMessageConverter.class)) {
                // Conversion to byte[] is done using first applicable configured HTTP message converter, corresponding String is returned
                return new String(convertEncryptedResponse(encryptedResponse, mediaType), StandardCharsets.UTF_8);
            } else {
                // Conversion to byte[] is done using first applicable configured HTTP message converter
                return convertEncryptedResponse(encryptedResponse, mediaType);
            }
        } catch (Exception ex) {
            logger.warn("Encryption failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
    }

    /**
     * Serialize response object to byte[].
     *
     * @param response Response object.
     * @return Response data as byte[].
     * @throws IOException In case JSON serialization fails.
     */
    private byte[] serializeResponseObject(Object response) throws IOException {
        if (response.getClass().equals(byte[].class)) {
            // Response data is raw byte[], data conversion is not required
            return (byte[]) response;
        } else {
            // Convert response object to byte[] using ObjectMapper
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            objectMapper.writeValue(baos, response);
            return baos.toByteArray();
        }
    }

    /**
     * Convert encrypted response to byte[] using first applicable HTTP message converter.
     *
     * @param encryptedResponse Encrypted response to convert.
     * @param mediaType Selected HTTP response media type.
     * @return Converted encrypted response.
     * @throws IOException In case serialization fails.
     */
    @SuppressWarnings("unchecked")
    private byte[] convertEncryptedResponse(EciesEncryptedResponse encryptedResponse, MediaType mediaType) throws IOException {
        final List<HttpMessageConverter<?>> httpMessageConverters = requestMappingHandlerAdapter.getMessageConverters();
        // Find the first applicable HTTP message converter for conversion
        for (HttpMessageConverter<?> converter: httpMessageConverters) {
            if (converter.canWrite(encryptedResponse.getClass(), mediaType)) {
                final BasicHttpOutputMessage httpOutputMessage = new BasicHttpOutputMessage();
                ((HttpMessageConverter<EciesEncryptedResponse>) converter).write(encryptedResponse, mediaType, httpOutputMessage);
                return httpOutputMessage.getBodyBytes();
            }
        }
        // Could not find any applicable converter, Spring is configured incorrectly
        throw new IOException("Response message conversion failed, no applicable HTTP message converter found");
    }

    private static class BasicHttpOutputMessage implements HttpOutputMessage {

        private final ByteArrayOutputStream os = new ByteArrayOutputStream();
        private final HttpHeaders httpHeaders = new HttpHeaders();

        @Override
        @NonNull
        public OutputStream getBody() {
            return os;
        }

        public byte[] getBodyBytes() {
            return os.toByteArray();
        }

        @Override
        @NonNull
        public HttpHeaders getHeaders() {
            return httpHeaders;
        }
    }

}
