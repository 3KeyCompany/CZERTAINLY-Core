package com.czertainly.core.util;

import com.czertainly.api.model.core.certificate.CertificateValidationCheckStatus;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class OcspUtil {
    private static final Logger logger = LoggerFactory.getLogger(OcspUtil.class);

    private OcspUtil() {

    }

    public static String getChainFromAia(X509Certificate certificate) throws IOException {
        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (octetBytes == null) {
            return null;
        }

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(octetBytes));
        AccessDescription[] descriptions = aia.getAccessDescriptions();
        for (AccessDescription ad : descriptions) {
            if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                GeneralName location = ad.getAccessLocation();
                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    logger.debug("Chain for the certificate is {}", location.getName());
                    return location.getName().toString();
                }
            }
        }
        return null;
    }

    public static List<String> getOcspUrlFromCertificate(X509Certificate certificate) {
        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        List<String> ocspUrls = new ArrayList<>();
        try {
            ASN1Primitive fromExtensionValue = JcaX509ExtensionUtils.parseExtensionValue(octetBytes);
            if (!(fromExtensionValue instanceof DLSequence))
                return ocspUrls;
            AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(fromExtensionValue);
            AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (AccessDescription accessDescription : accessDescriptions) {
                boolean correctAccessMethod = accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
                if (!correctAccessMethod) {
                    continue;
                }
                GeneralName name = accessDescription.getAccessLocation();
                if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    continue;
                }
                DERIA5String derStr = (DERIA5String) DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
                String ocspUrl = derStr.getString();
                logger.debug("OCSP URL Of the certificate is {}", ocspUrl);
                ocspUrls.add(ocspUrl);
            }
        } catch (Exception e) {
            logger.debug("Error while getting OCSP URL: {}", e.getMessage());
        }
        logger.debug("OCSP URL for the certificate is not available");
        return ocspUrls;
    }

    public static CertificateValidationCheckStatus checkOcsp(X509Certificate certificate, X509Certificate issuer, String serviceUrl) throws Exception {
        logger.debug("OCSP Check URL is {}", serviceUrl);
        OCSPReq request = generateOCSPRequest(issuer, certificate.getSerialNumber());
        OCSPResp ocspResponse = getOCSPResponse(serviceUrl, request);
        if (OCSPResponseStatus.SUCCESSFUL == ocspResponse.getStatus())
            logger.debug("OCSP Server responded with status");

        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
        SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();

        if (responses != null && responses.length == 1) {
            SingleResp resp = responses[0];
            Object status = resp.getCertStatus();
            if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                logger.debug("OCSP Check Success. Certificate is valid");
                return CertificateValidationCheckStatus.SUCCESS;
            } else if (status instanceof RevokedStatus) {
                logger.debug("OCSP Check Failed. Certificate is revoked");
                return CertificateValidationCheckStatus.REVOKED;
            } else if (status instanceof UnknownStatus) {
                logger.debug("OCSP Check Unknown");
                return CertificateValidationCheckStatus.WARNING;
            }
        }
        logger.debug("OCSP Check Unknown.");
        return CertificateValidationCheckStatus.WARNING;
    }

    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws OCSPException, IOException, OperatorException, CertificateEncodingException {
        JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
        CertificateID id = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuerCert), serialNumber);
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(id);
        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(nonce.toByteArray()));
        gen.setRequestExtensions(new Extensions(new Extension[]{ext}));

        return gen.build();
    }

    private static OCSPResp getOCSPResponse(String serviceUrl, OCSPReq request) throws IOException {

        try {
            byte[] array = request.getEncoded();
            if (serviceUrl.startsWith("http")) {
                URL url = new URL(serviceUrl);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                dataOut.write(array);

                dataOut.flush();
                dataOut.close();

                // Get Response
                InputStream in = (InputStream) con.getContent();
                return new OCSPResp(in);
            } else {
                throw new IllegalArgumentException("Only http is supported for OCSP requests");
            }
        } catch (IOException e) {
            logger.debug("Failed to connect to OCSP URL");
            throw new IOException("Cannot get OCSP response from URL: " + serviceUrl, e);
        }
    }
}
