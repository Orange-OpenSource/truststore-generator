# truststore-generator [![Build Status](https://travis-ci.org/Orange-OpenSource/truststore-generator.svg?branch=master)](https://travis-ci.org/Orange-OpenSource/truststore-generator)

Generate a [java SSL truststore](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#CustomizingStores) from [json](https://en.wikipedia.org/wiki/JSON) representation.

Here is a sample of [json](https://en.wikipedia.org/wiki/JSON) truststore representation :

{"certificates":["-----BEGIN CERTIFICATE-----\r\nMIIDhzCCAm+gAwIBAgIEYmqHlTANBgkqhkiG9w0BAQsFADB0MRAwDgYDVQQGEwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRYwFAYDVQQKEw13b3JsZCBjb21wYW55MRAwDgYDVQQLEwdVbmtub3duMRIwEAYDVQQDEwlqb2huIHBhdWwwHhcNMTUxMDI5MTQzNjEwWhcNMTYwMTI3MTQzNjEwWjB0MRAwDgYDVQQGEwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRYwFAYDVQQKEw13b3JsZCBjb21wYW55MRAwDgYDVQQLEwdVbmtub3duMRIwEAYDVQQDEwlqb2huIHBhdWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+UGMvPPnJowZcE5KI+FSyg8kCJtXLAK59e9JqMnbzzJUX3RQfT2BH08xN0z+cGdqOQNV7gvf2TCEJYOwFqB60JEhIgNPXGY/xOcFHY7qm+5MMXSvkxPw4yCEFj1vxfGY8kBKXWknhmE2eXG2S+bVSmwo9IBOHXgFzhOqmQly1uLP1x06NtpJV9lTWHBECWa7fIBmMUkXCrxdqVJb/OFjkjrmBhFjYhjTi+syqxO/blQiDDfGlOGTvf37ivcUtXQIvH2qce2vQuP+iZA/f5levMdySa6+Vdfdi114V83HjAsJGWStz0K2W5QRw/3ilw2D0hyCRKavOQBtG5m+o3v29AgMBAAGjITAfMB0GA1UdDgQWBBTe/Jg26TgrkhLLWBMH
vinQzM4r0DANBgkqhkiG9w0BAQsFAAOCAQEAC7I3O4qNGF8KfWvJYXAcTW3cRTTzctEqaZvkR7biNoyhT6FykuCEgmrKId6HSaOCQEHp8h9/IHh/pwWFFNrIBCsPbyZBggTKC2Hj/dna/T7Ejoqsg3pXytDIlnDSPi3vsUcyLMpC1qZKRk5mYto6fxsb48IcFTyytQygcdvcYgGe5yQasYL4s55k9whwNbrzYHaWU3uNc3UVjyxkKAufrOQdWktg
hIGlTE8Wm4gNNZx116hbCyFmK7UKOufRyW0pF1UcicfkaPs4Dd1ApU79uifvvN9PmjPkk88buTsMqzvkfey8HBaoZb9AiVYPn2if8HINvCOKaaLe7ixzgBGNkg==\r\n-----END CERTIFICATE-----"]}

## Building

To build the source you will need to install JDK 1.8.

truststore-generator uses Maven

```
$ ./mvn install
```

## Usage

To benefit from truststore generation, add truststore-generator dependency to your application.

Example for maven

```
        <dependency>
            <groupId>com.orange.clara.cloud.truststore</groupId>
            <artifactId>truststore-generator</artifactId>
            <version>0.1-SNAPSHOT</version>
        </dependency>
```
