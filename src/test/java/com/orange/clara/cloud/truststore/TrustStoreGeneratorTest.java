package com.orange.clara.cloud.truststore;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.Certificate;
import java.util.ArrayList;

/**
 * Created by sbortolussi on 05/11/2015.
 */
public class TrustStoreGeneratorTest {

    public static final String CERTIFICATE = "-----BEGIN CERTIFICATE-----\r\n" +
            "MIIDhzCCAm+gAwIBAgIEYmqHlTANBgkqhkiG9w0BAQsFADB0MRAwDgYDVQQGEwdV\r\n" +
            "bmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRYwFAYD\r\n" +
            "VQQKEw13b3JsZCBjb21wYW55MRAwDgYDVQQLEwdVbmtub3duMRIwEAYDVQQDEwlq\r\n" +
            "b2huIHBhdWwwHhcNMTUxMDI5MTQzNjEwWhcNMTYwMTI3MTQzNjEwWjB0MRAwDgYD\r\n" +
            "VQQGEwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3du\r\n" +
            "MRYwFAYDVQQKEw13b3JsZCBjb21wYW55MRAwDgYDVQQLEwdVbmtub3duMRIwEAYD\r\n" +
            "VQQDEwlqb2huIHBhdWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+\r\n" +
            "UGMvPPnJowZcE5KI+FSyg8kCJtXLAK59e9JqMnbzzJUX3RQfT2BH08xN0z+cGdqO\r\n" +
            "QNV7gvf2TCEJYOwFqB60JEhIgNPXGY/xOcFHY7qm+5MMXSvkxPw4yCEFj1vxfGY8\r\n" +
            "kBKXWknhmE2eXG2S+bVSmwo9IBOHXgFzhOqmQly1uLP1x06NtpJV9lTWHBECWa7f\r\n" +
            "IBmMUkXCrxdqVJb/OFjkjrmBhFjYhjTi+syqxO/blQiDDfGlOGTvf37ivcUtXQIv\r\n" +
            "H2qce2vQuP+iZA/f5levMdySa6+Vdfdi114V83HjAsJGWStz0K2W5QRw/3ilw2D0\r\n" +
            "hyCRKavOQBtG5m+o3v29AgMBAAGjITAfMB0GA1UdDgQWBBTe/Jg26TgrkhLLWBMH\r\n" +
            "vinQzM4r0DANBgkqhkiG9w0BAQsFAAOCAQEAC7I3O4qNGF8KfWvJYXAcTW3cRTTz\r\n" +
            "ctEqaZvkR7biNoyhT6FykuCEgmrKId6HSaOCQEHp8h9/IHh/pwWFFNrIBCsPbyZB\r\n" +
            "ggTKC2Hj/dna/T7Ejoqsg3pXytDIlnDSPi3vsUcyLMpC1qZKRk5mYto6fxsb48Ic\r\n" +
            "FTyytQygcdvcYgGe5yQasYL4s55k9whwNbrzYHaWU3uNc3UVjyxkKAufrOQdWktg\r\n" +
            "hIGlTE8Wm4gNNZx116hbCyFmK7UKOufRyW0pF1UcicfkaPs4Dd1ApU79uifvvN9P\r\n" +
            "mjPkk88buTsMqzvkfey8HBaoZb9AiVYPn2if8HINvCOKaaLe7ixzgBGNkg==\r\n" +
            "-----END CERTIFICATE-----";

    @Before
    public void setup(){
        Assert.assertNull(System.getProperty(TrustStoreGenerator.SSL_TRUST_STORE_SYSTEM_PROPERTY));
        Assert.assertNull(System.getProperty(TrustStoreGenerator.SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY));
    }

    @Test
    public void should_generate_truststore() throws Exception {
        final ArrayList<Certificate> certificates = new ArrayList<>();
        certificates.add(new CertificateFactory().newInstance(CERTIFICATE));
        certificates.add(new CertificateFactory().newInstance(CERTIFICATE));
        TrustStoreProperty trustStoreProperty = new TrustStoreProperty(certificates);
        TrustStoreGenerator trustStoreGenerator = new TrustStoreGenerator();
        trustStoreGenerator.generate(trustStoreProperty);
        Assert.assertNotNull(System.getProperty(TrustStoreGenerator.SSL_TRUST_STORE_SYSTEM_PROPERTY));
        Assert.assertNotNull(System.getProperty(TrustStoreGenerator.SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY));
    }
}