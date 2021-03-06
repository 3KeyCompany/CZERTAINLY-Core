package com.czertainly.core.util;

import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Base64;

public class CsrUtil {
    private static final Logger logger = LoggerFactory.getLogger(CsrUtil.class);

    public static JcaPKCS10CertificationRequest csrStringToJcaObject(String csr) throws IOException {
        csr = csr.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("\r", "").replace("\n", "")
                .replace("-----END CERTIFICATE REQUEST-----", "");

        // some of the X.509 CSRs can have different headers and footers
        csr = csr.replace("-----BEGIN NEW CERTIFICATE REQUEST-----", "")
                .replace("\r", "").replace("\n", "")
                .replace("-----END NEW CERTIFICATE REQUEST-----", "");

        logger.debug("Decoding Base64-encoded CSR: " + csr);
        byte[] decoded = Base64.getDecoder().decode(csr);
        return new JcaPKCS10CertificationRequest(decoded);
    }
}
