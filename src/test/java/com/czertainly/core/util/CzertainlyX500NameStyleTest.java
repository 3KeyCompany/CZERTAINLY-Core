package com.czertainly.core.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CzertainlyX500NameStyleTest {
    private static final Logger logger = LoggerFactory.getLogger(CzertainlyX500NameStyleTest.class);

    @Test
    public void testCustomNameStyle() throws CertificateException {
        Assertions.assertEquals("CN=Certificate Authority, L=Location, ST=State, C=US, O=Organization", getDnWithCustomStyle("CN=Certificate Authority; L=Location,ST=State, C=US;O=Organization"));
        Assertions.assertEquals("2.5.4.10=Organization,2.5.4.3=Certificate Authority,2.5.4.6=US,2.5.4.7=Location,2.5.4.8=State", getDnWithCustomStyleNormalized("CN=Certificate Authority; L=Location,ST=State, C=US;O=Organization"));
        Assertions.assertEquals("CN=Example Root CA, O=Example Corp, EMAIL=admin@example.com, C=US", getDnWithCustomStyle("CN=Example Root CA; O=Example Corp; EMAILADDRESS=admin@example.com,C=US"));
        Assertions.assertEquals("1.2.840.113549.1.9.1=admin@example.com,2.5.4.10=Example Corp,2.5.4.3=Example Root CA,2.5.4.6=US", getDnWithCustomStyleNormalized("CN=Example Root CA; O=Example Corp; EMAILADDRESS=admin@example.com,C=US"));
        Assertions.assertEquals("OU=IT Security, O=SecureCorp, L=City, ST=State, C=US, 2.5.4.77=SSL Issuer", getDnWithCustomStyle("OU=IT Security; O=SecureCorp; L=City; ST=State; C=US, 2.5.4.77=SSL Issuer"));
        Assertions.assertEquals("2.5.4.10=SecureCorp,2.5.4.11=IT Security,2.5.4.6=US,2.5.4.7=City,2.5.4.77=SSL Issuer,2.5.4.8=State", getDnWithCustomStyleNormalized("OU=IT Security; O=SecureCorp; L=City; ST=State; C=US, 2.5.4.77=SSL Issuer"));
        X509Certificate certificateAVA = CertificateUtil.getX509Certificate(("MIIEBjCCAu6gAwIBAgIUb2wDIxFx4Ma6mtoWuFPoPFULDR8wDQYJKoZIhvcNAQELBQAwgYExDDAKBgNVBAMMA0FiYzEMMAoGA1UEAwwDQmNkMQ4wDAYDVQQDDAVYeXp6eTELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTEPMA0GA1UEBwwGUHJhZ3VlMQ8wDQYDVQQHDAZMb25kb24xEzARBgNVBAcMCkJyYXRpc2xhdmEwHhcNMjMxMTEwMTEwNDUzWhcNMjQxMTA5MTEwNDUzWjCBgTEMMAoGA1UEAwwDQWJjMQwwCgYDVQQDDANCY2QxDjAMBgNVBAMMBVh5enp5MQswCQYDVQQGEwJDWjEPMA0GA1UECAwGUHJhZ3VlMQ8wDQYDVQQHDAZQcmFndWUxDzANBgNVBAcMBkxvbmRvbjETMBEGA1UEBwwKQnJhdGlzbGF2YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALa3Th//z2GeyFFtlUmBdwYIww5dTZqHihaBLhfkUtS+fhetHRDlWXcBaCFYT/SB44+rXh3F6iADWW4oB2KQLEaqUG7cP651Ni2e2hag2pny36P5lrSi0uhRcGbDikixCAXauif9iJRwcNCZQYGgq0/FrROikyFMxVx5BxWOVjmD0M36tR+kCE0pKdqRfwKGZ1gb0rLmH6XQhz26Whb0+BFT5WnUxFUMvtm8GpwN8RufP/YvSyTGQNnODm2+VMctJ/fk5tYQowciTnhZvcFCBui50XRJPN1kjSKgoJkNongbmi0nWqy24Hv3fLC01dVND0vnNcqmcrFpmCeYE4cHRxECAwEAAaN0MHIwHQYDVR0OBBYEFEPtLZm3Uxd9hVEAw0mmlc4uEmwcMB8GA1UdIwQYMBaAFEPtLZm3Uxd9hVEAw0mmlc4uEmwcMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAC/3uvlM3hbHtk9FOAfj7tmjWqXk1at8mNyOY/0SDauSWQk1VGgf66pPjccq72dfYcpfh17cswyTX/ZF5Kj2nZ9uv09tBL+yZL+FJBJ6e/1s53bY3XKlbB6qJUG+cebpUiYqOf+yuPYGDokBa6/aA1XtgkgaIMq06N/Wvl0/dvXnMz+EDPQsApbM96yl23QGhezdebYh7VM7qiDl5CNuGnidZkm4tUNq3F1aBnVPPADmxOfdVkdDwJbfjluozBDZIRW14lixbzBWx2WVz/m090r/zPERhCcghVvYEnKUIp683UT+SrJNKZhCrqWL45KzMheLbB5GRQWTo1euXJT0Vec="));
        X509Certificate certificateO = CertificateUtil.getX509Certificate("MIIEDjCCAvagAwIBAgIUZ0CT63uIZ4fMvIqM5k8lGT+nZOAwDQYJKoZIhvcNAQELBQAwgYUxEDAOBgNVBAMMB2NvbXAuZXUxCzAJBgNVBAYTAkNaMQ8wDQYDVQQIDAZQcmFndWUxDzANBgNVBAcMBlByYWd1ZTEUMBIGA1UECgwLT3JnLCBzLnIuby4xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMQ0wCwYDVQQFEwQxMjM0MB4XDTIzMTExMDExMTQwM1oXDTI0MTEwOTExMTQwM1owgYUxEDAOBgNVBAMMB2NvbXAuZXUxCzAJBgNVBAYTAkNaMQ8wDQYDVQQIDAZQcmFndWUxDzANBgNVBAcMBlByYWd1ZTEUMBIGA1UECgwLT3JnLCBzLnIuby4xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMQ0wCwYDVQQFEwQxMjM0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzLQ+JnQEQVQH1ygGaVfmR+SfrowGcNfCDZ+rg97eCzFBzkeCPiFHa8A6f/Zc8vZeKUTvepAFQ7fd2rh5kjQMgAb4fIOtFL7+SfEH+Hn0g7Te+4UuxZKRQax5nsTEo1s8XFrE3cNRhB3bxKj+b8cOndoGaDVsLXy9X9UGMwfdYbtkSgdzHOeGVsPsc7ppn2xo8vm+CDi5rEIQlvopeshrAKPXa8cgM9HgwxhdIpj5/7CvswxOvlEzeDT7MbUoPKiVQKO/RDixa50Eov4wENlQS3OxwvkBYa2STnBO7iooQGmtbnyQsHnbW4RxyhYgyTPXK1K+ssSsNW5KTdjp2VZkcQIDAQABo3QwcjAdBgNVHQ4EFgQUinfVgYajVU8ySmBRcLzgU/M4IX8wHwYDVR0jBBgwFoAUinfVgYajVU8ySmBRcLzgU/M4IX8wDgYDVR0PAQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEACAQLiLbysA9kCL0Di5Rfp/cg/qfBr0udWr1EwrO5p4MsgNgTAMpD15DbtSefw9FPralH9hmkxdNH5OmMtHuoBc+6S63iIZ4zq4/V5mJTmd675UPu7N3SQNXAN5A8klFv0rW0E/O5uZaPEv/CaM+zO3fHpJvrGn+dVHWPU2Q2yCMCy6ikuzshb0yjw5FH7TEPjgkobygd2gGWMVk2ZOKAKImBDf7f6PMi/AXKkucaTf5XV+SucN9DXUx3ukCDEdEoqzjW+s2xx7TRATm6j1PFfGKNNBOxQnAYQAYOSp38TKo9EsTqAt+YvlTrlVuKJQBOHJ2/rqCiQfZ1Vid7/9nuKA==");
        Assertions.assertEquals("L=Bratislava, L=London, L=Prague, ST=Prague, C=CZ, CN=Xyzzy, CN=Bcd, CN=Abc", X500Name.getInstance(CzertainlyX500NameStyle.DEFAULT, certificateAVA.getSubjectX500Principal().getEncoded()).toString());
        Assertions.assertEquals("2.5.4.3=Abc,2.5.4.3=Bcd,2.5.4.3=Xyzzy,2.5.4.6=CZ,2.5.4.7=Bratislava,2.5.4.7=London,2.5.4.7=Prague,2.5.4.8=Prague", X500Name.getInstance(CzertainlyX500NameStyle.NORMALIZED, certificateAVA.getSubjectX500Principal().getEncoded()).toString());
        Assertions.assertEquals("SERIALNUMBER=1234, BusinessCategory=Private Organization, O=Org, s.r.o., L=Prague, ST=Prague, C=CZ, CN=comp.eu", X500Name.getInstance(CzertainlyX500NameStyle.DEFAULT, certificateO.getSubjectX500Principal().getEncoded()).toString());
        Assertions.assertEquals("2.5.4.10=Org, s.r.o.,2.5.4.15=Private Organization,2.5.4.3=comp.eu,2.5.4.5=1234,2.5.4.6=CZ,2.5.4.7=Prague,2.5.4.8=Prague", X500Name.getInstance(CzertainlyX500NameStyle.NORMALIZED, certificateO.getSubjectX500Principal().getEncoded()).toString());
    }

    private String getDnWithCustomStyle(String dn) {
        return X500Name.getInstance(CzertainlyX500NameStyle.DEFAULT, new X500Principal(dn).getEncoded()).toString();
    }

    private String getDnWithCustomStyleNormalized(String dn) {
        return X500Name.getInstance(CzertainlyX500NameStyle.NORMALIZED, new X500Principal(dn).getEncoded()).toString();
    }
}


