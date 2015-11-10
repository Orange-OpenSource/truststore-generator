/*
 *
 *  * Copyright (C) 2015 Orange
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 *
 */

package com.orange.clara.cloud.truststore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;


/**
 * Created by sbortolussi on 28/10/2015.
 *
 * credits to https://github.com/cloudfoundry/cf-java-client/blob/master/cloudfoundry-client-spring/src/main/java/org/cloudfoundry/client/spring/util/CertificateCollectingSslCertificateTruster.java
 */
public class TrustStoreGenerator {

    public static final String SSL_TRUST_STORE_SYSTEM_PROPERTY = "javax.net.ssl.trustStore";
    public static final String SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY = "javax.net.ssl.trustStorePassword";
    public static final String TRUSTSTORE_FILENAME = "truststore";

    private static Logger LOGGER = LoggerFactory.getLogger(TrustStoreGenerator.class);

     public void generate(TrustStoreProperty trustStoreProperty) {
         try {
             String password = UUID.randomUUID().toString();

             final File trustStoreFile = getTrustStore(trustStoreProperty.getCertificates(),password);

             System.setProperty(SSL_TRUST_STORE_SYSTEM_PROPERTY, trustStoreFile.getAbsolutePath());
             LOGGER.info("Setting " + SSL_TRUST_STORE_SYSTEM_PROPERTY + " system property to " + trustStoreFile.getAbsolutePath());
             System.setProperty(SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY, password);
             LOGGER.info("Setting " + SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY + " system property to " + password);
         } catch (Exception e) {
             throw new IllegalStateException(e);
         }
     }

    protected File getTrustStore(List<Certificate> chain,String password) throws KeyStoreException, NoSuchAlgorithmException,
            IOException, CertificateException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);

        for (X509Certificate cert : getDefaultTrustManager().getAcceptedIssuers()) {
            trustStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
        }

        for (Certificate cert : chain) {
            trustStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
        }

        File trustStoreOutputFile = File.createTempFile(TRUSTSTORE_FILENAME, null);
        trustStoreOutputFile.deleteOnExit();
        trustStore.store(new FileOutputStream(trustStoreOutputFile), password.toCharArray());

        return  trustStoreOutputFile;
    }

    private X509TrustManager getDefaultTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        return (X509TrustManager) factory.getTrustManagers()[0];
    }

}
