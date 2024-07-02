package com.czertainly.core.validation.certificate;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationCheck;
import com.czertainly.api.model.core.certificate.CertificateValidationCheckDto;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Crl;
import com.czertainly.core.dao.entity.CrlEntry;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.CrlEntryRepository;
import com.czertainly.core.dao.repository.CrlRepository;
import com.czertainly.core.service.CrlService;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.CrlUtil;
import com.czertainly.core.util.CzertainlyX500NameStyle;
import com.czertainly.core.util.OcspUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service("X.509")
public class X509CertificateValidator implements ICertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidator.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int DAYS_TO_EXPIRE = 30;
    private CertificateRepository certificateRepository;


    private CrlService crlService;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCrlService(CrlService crlService) {
        this.crlService = crlService;
    }


    @Override
    public CertificateValidationStatus validateCertificate(Certificate certificate, boolean isCompleteChain) throws CertificateException {
        logger.debug("Initiating the certificate validation: {}", certificate);

        ArrayList<Certificate> certificateChain = new ArrayList<>();
        Certificate lastCertificate = certificate;
        do {
            certificateChain.add(lastCertificate);
            lastCertificate = lastCertificate.getIssuerCertificateUuid() == null ? null : certificateRepository.findByUuid(lastCertificate.getIssuerCertificateUuid()).orElse(null);
        } while (lastCertificate != null);

        X509Certificate x509Certificate;
        X509Certificate x509IssuerCertificate = null;
        CertificateValidationStatus previousCertStatus = CertificateValidationStatus.NOT_CHECKED;
        Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput;
        for (int i = certificateChain.size() - 1; i >= 0; i--) {
            // initialization by preparing X509Certificate object
            x509Certificate = CertificateUtil.getX509Certificate(certificateChain.get(i).getCertificateContent().getContent());

            boolean isEndCertificate = i == 0;
            validationOutput = validatePathCertificate(x509Certificate, x509IssuerCertificate, certificateChain.get(i).getTrustedCa(), previousCertStatus, isCompleteChain, isEndCertificate, certificateChain.get(i).getIssuerDnNormalized());
            CertificateValidationStatus resultStatus = calculateResultStatus(validationOutput);
            finalizeValidation(certificateChain.get(i), resultStatus, validationOutput);

            previousCertStatus = resultStatus;
            x509IssuerCertificate = x509Certificate;
        }

        logger.debug("Certificate validation of {} finalized with result: {}", certificate, previousCertStatus);
        return previousCertStatus;
    }

    private Map<CertificateValidationCheck, CertificateValidationCheckDto> validatePathCertificate(X509Certificate certificate, X509Certificate issuerCertificate, Boolean trustedCa, CertificateValidationStatus issuerCertificateStatus, boolean isCompleteChain, boolean isEndCertificate, String issuerDn) {
        Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput = initializeValidationOutput();

        // check certificate signature
        // section (a)(1) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.SIGNATURE_VERIFICATION, checkCertificateSignature(certificate, issuerCertificate, isCompleteChain));

        // check certificate validity
        // section (a)(2) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_VALIDITY, checkCertificateValidity(certificate));

        // check if certificate is not revoked - OCSP & CRL
        // section (a)(3) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.OCSP_VERIFICATION, checkOcspRevocationStatus(certificate, issuerCertificate));
        validationOutput.put(CertificateValidationCheck.CRL_VERIFICATION, checkCrlRevocationStatus(certificate, issuerCertificate, isCompleteChain));

        // check certificate issuer DN and if certificate chain is valid
        // section (a)(4) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_CHAIN, checkCertificateChain(certificate, issuerCertificate, trustedCa, issuerCertificateStatus, isCompleteChain));

        // (k) and (l) section in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4
        validationOutput.put(CertificateValidationCheck.BASIC_CONSTRAINTS, checkBasicConstraints(certificate, issuerCertificate, isEndCertificate));

        // (n) section in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4
        validationOutput.put(CertificateValidationCheck.KEY_USAGE, checkKeyUsage(certificate));

        return validationOutput;
    }

    private CertificateValidationCheckDto checkCertificateChain(X509Certificate certificate, X509Certificate issuerCertificate, Boolean isTrustedCa, CertificateValidationStatus issuerCertificateStatus, boolean isCompleteChain) {
        if (issuerCertificate == null) {
            // should be trust anchor (Root CA certificate or self-signed certificate)
            if (isCompleteChain) {
                String certificateType = "self-signed";
                // Check if certificate is CA, for CA certificate is this value always > -1
                if (certificate.getBasicConstraints() > -1)  certificateType = "root CA";
                if (Boolean.TRUE.equals(isTrustedCa)) {
                    return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.VALID, "Certificate chain is complete. Certificate is trusted " + certificateType + " certificate.");
                } else {
                    return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.INVALID, "Certificate chain is complete. Certificate is " + certificateType + " certificate but not marked as trusted.");
                }
            } else {
                return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.INVALID, "Incomplete certificate chain. Issuer certificate is not available in the inventory or in the AIA extension.");
            }
        } else {
            String issuerStatusMessage = "";
            if (issuerCertificateStatus.equals(CertificateValidationStatus.INVALID) || issuerCertificateStatus.equals(CertificateValidationStatus.REVOKED)) {
                issuerStatusMessage = String.format(" Issuer certificate is %s.", issuerCertificateStatus.getLabel());
            }

            String issuerNameEqualityMessage = "";
            if (!issuerCertificate.getSubjectX500Principal().getName().equals(certificate.getIssuerX500Principal().getName())) {
                issuerNameEqualityMessage = " Issuer DN does not equal to issuer certificate subject DN.";
            }

            if (isCompleteChain) {
                String trustedCaMessage = "";
                if (isTrustedCa != null) {
                    trustedCaMessage = Boolean.TRUE.equals(isTrustedCa) ? " Certificate is trusted intermediate CA." : " Certificate is intermediate CA certificate but not marked as trusted.";
                }

                CertificateValidationStatus chainValidationStatus = issuerNameEqualityMessage.isEmpty() && issuerStatusMessage.isEmpty() && (trustedCaMessage.isEmpty() || Boolean.TRUE.equals(isTrustedCa)) ? CertificateValidationStatus.VALID : CertificateValidationStatus.INVALID;
                return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, chainValidationStatus, "Certificate chain is complete.%s%s%s".formatted(trustedCaMessage, issuerNameEqualityMessage, issuerStatusMessage));
            } else {
                return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.INVALID, "Incomplete certificate chain. Missing certificate in validation path.%s%s".formatted(issuerNameEqualityMessage, issuerStatusMessage));
            }
        }
    }

    private CertificateValidationCheckDto checkCertificateSignature(X509Certificate certificate, X509Certificate issuerCertificate, boolean isCompleteChain) {
        if (issuerCertificate == null) { // self-signed root CA
            if (!isCompleteChain) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Issuer certificate is not available.");
            }

            if (verifySignature(certificate, certificate)) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.VALID, "Self-signed signature verification successful.");
            } else {
                return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.FAILED, "Self-signed signature verification failed.");
            }
        } else {
            if (verifySignature(certificate, issuerCertificate)) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.VALID, "Signature verification successful.");
            } else {
                return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.FAILED, "Signature verification failed.");
            }
        }
    }

    private CertificateValidationCheckDto checkCertificateValidity(X509Certificate certificate) {
        long millisToExpiry;
        Date currentUtcDate = Date.from(Instant.now());
        Date notAfterDate = certificate.getNotAfter();
        Date notBeforeDate = certificate.getNotBefore();
        if (notBeforeDate.after(currentUtcDate)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.INACTIVE, "Certificate is inactive (not valid yet).");
        } else if (currentUtcDate.after(notAfterDate)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.EXPIRED, "Certificate is expired.");
        } else if ((millisToExpiry = notAfterDate.getTime() - currentUtcDate.getTime()) < TimeUnit.DAYS.toMillis(DAYS_TO_EXPIRE)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.EXPIRING, "Certificate will expire in " + convertMillisecondsToTimeString(millisToExpiry));
        } else {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.VALID, "Certificate is valid.");
        }
    }

    private CertificateValidationCheckDto checkOcspRevocationStatus(X509Certificate certificate, X509Certificate issuerCertificate) {
        if (issuerCertificate == null) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Issuer certificate is not available.");
        }

        List<String> ocspUrls;
        try {
            ocspUrls = OcspUtil.getOcspUrlFromCertificate(certificate);
        } catch (IOException e) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.FAILED, "Failed to retrieve OCSP URL from certificate: " + e.getMessage());
        }

        if (ocspUrls.isEmpty()) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Certificate does not contain AIA extension or OCSP URL is not present");
        }

        StringBuilder ocspMessage = new StringBuilder();
        CertificateValidationStatus ocspOutputStatus = CertificateValidationStatus.NOT_CHECKED;
        for (String ocspUrl : ocspUrls) {
            try {
                CertificateValidationStatus ocspStatus = OcspUtil.checkOcsp(certificate, issuerCertificate, ocspUrl);
                if (ocspStatus.equals(CertificateValidationStatus.VALID)) {
                    if (ocspOutputStatus.equals(CertificateValidationStatus.NOT_CHECKED)) {
                        ocspOutputStatus = ocspStatus;
                    }
                    ocspMessage.append("OCSP verification successful from URL ");
                    ocspMessage.append(ocspUrl);
                    ocspMessage.append(". ");
                } else if (ocspStatus.equals(CertificateValidationStatus.REVOKED)) {
                    ocspOutputStatus = ocspStatus;
                    ocspMessage.append("Certificate was revoked according to information from OCSP URL ");
                    ocspMessage.append(ocspUrl);
                    ocspMessage.append(". ");
                    break;
                } else {
                    ocspOutputStatus = ocspStatus;
                    ocspMessage.append("OCSP Check result is unknown from URL ");
                    ocspMessage.append(ocspUrl);
                    ocspMessage.append(". ");
                }
            } catch (Exception e) {
                logger.debug("Not able to check OCSP: {}", e.getMessage());
                ocspOutputStatus = CertificateValidationStatus.FAILED;
                ocspMessage.append("Error while checking OCSP URL ");
                ocspMessage.append(ocspUrl);
                ocspMessage.append(". Error: ");
                ocspMessage.append(e.getMessage());
                ocspMessage.append(". ");
            }
        }

        return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, ocspOutputStatus, ocspMessage.toString());
    }

    private CertificateValidationCheckDto checkCrlRevocationStatus(X509Certificate certificate, X509Certificate issuerCertificate, boolean isCompleteChain) {
        if (issuerCertificate == null) {
            if (!isCompleteChain)
                return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Issuer certificate is not available.");
            issuerCertificate = certificate;
        }

        if (certificate.getExtensionValue(Extension.cRLDistributionPoints.getId()) == null) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "The cRLDistributionPoints extension is not set.");
        }
        Crl crl;
        try {
            crl = crlService.getCurrentCrl(certificate, issuerCertificate);
        } catch (IOException e) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.FAILED, "Failed to retrieve CRL URL from certificate: " + e.getMessage());
        } catch (ValidationException e) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.FAILED, "Failed to process CRL: " + e.getMessage());
        }

        if (crl == null) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "No available working CRL URL found in cRLDistributionPoints extension.");
        }

        StringBuilder crlMessage = new StringBuilder();
        CertificateValidationStatus crlOutputStatus;

        CrlEntry crlEntry = crlService.findCrlEntryForCertificate(certificate.getSerialNumber().toString(16), crl.getUuid());

        if (crlEntry == null) {
            crlOutputStatus = CertificateValidationStatus.VALID;
            crlMessage.append("CRL verification successful from URL");
            crlMessage.append(". ");
        } else {
            crlOutputStatus = CertificateValidationStatus.REVOKED;
            crlMessage.append("Certificate was revoked according to information from CRL URL");
            crlMessage.append(". Revocation reason: ");
            crlMessage.append(crlEntry.getRevocationReason().getLabel());
            crlMessage.append(". ");
        }
        return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, crlOutputStatus, crlMessage.toString());
    }


    private CertificateValidationCheckDto checkBasicConstraints(X509Certificate certificate, X509Certificate issuerCertificate, boolean isEndCertificate) {
        int pathLenConstraint = certificate.getBasicConstraints();
        boolean isCa = pathLenConstraint >= 0;

        if (!isCa) {
            if (certificate.getVersion() == 3 && !isEndCertificate) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.INVALID, "Certificate is not end certificate in chain and is not marked as CA");
            } else if (certificate.getVersion() != 3) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.FAILED, "Certificate is not last in chain and cannot verify if it is a CA certificate");
            }
        } else if (issuerCertificate != null && pathLenConstraint > issuerCertificate.getBasicConstraints()) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.INVALID, "Certificate path length is greater than path length in issuer certificate");
        }

        return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.VALID, "Certificate basic constraints verification successful.");
    }

    private CertificateValidationCheckDto checkKeyUsage(X509Certificate certificate) {
        boolean isCa = certificate.getBasicConstraints() >= 0;

        if (!isCa) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.NOT_CHECKED, "Certificate is not CA.");
        }

        if (CertificateUtil.isKeyUsagePresent(certificate.getKeyUsage(), CertificateUtil.KEY_USAGE_KEY_CERT_SIGN)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.VALID, "Certificate keyCertSign bit is set and can be used to verify signatures on other certificates.");
        } else {
            return new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.INVALID, "Certificate keyCertSign bit is not set and cannot be used to verify signatures on other certificates.");
        }
    }

    private CertificateValidationStatus calculateResultStatus(Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput) {
        CertificateValidationCheckDto certificateValidationDto = validationOutput.get(CertificateValidationCheck.CERTIFICATE_CHAIN);
        if (!certificateValidationDto.getStatus().equals(CertificateValidationStatus.VALID)) {
            return CertificateValidationStatus.INVALID;
        }
        certificateValidationDto = validationOutput.get(CertificateValidationCheck.SIGNATURE_VERIFICATION);
        if (!certificateValidationDto.getStatus().equals(CertificateValidationStatus.VALID)) {
            return CertificateValidationStatus.INVALID;
        }

        CertificateValidationCheckDto validityCertificateValidationDto = validationOutput.get(CertificateValidationCheck.CERTIFICATE_VALIDITY);
        if (validityCertificateValidationDto.getStatus().equals(CertificateValidationStatus.INACTIVE)) {
            return CertificateValidationStatus.INACTIVE;
        }
        if (validityCertificateValidationDto.getStatus().equals(CertificateValidationStatus.EXPIRED)) {
            return CertificateValidationStatus.EXPIRED;
        }

        if (validationOutput.get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED)
                || validationOutput.get(CertificateValidationCheck.CRL_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED)) {
            return CertificateValidationStatus.REVOKED;
        }

        if (validityCertificateValidationDto.getStatus().equals(CertificateValidationStatus.EXPIRING)) {
            return CertificateValidationStatus.EXPIRING;
        }

        return CertificateValidationStatus.VALID;
    }

    private void finalizeValidation(Certificate certificate, CertificateValidationStatus resultStatus, Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput) throws CertificateException {
        certificate.setValidationStatus(resultStatus);
        certificate.setStatusValidationTimestamp(LocalDateTime.now());

        // change certificate state to revoked if applicable
        if (certificate.getState() == CertificateState.ISSUED
                && (validationOutput.get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED)
                || validationOutput.get(CertificateValidationCheck.CRL_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED))) {
            certificate.setState(CertificateState.REVOKED);
        }

        try {
            certificate.setCertificateValidationResult(OBJECT_MAPPER.writeValueAsString(validationOutput));
            certificateRepository.save(certificate);
        } catch (Exception e) {
            throw new CertificateException("Error in serialization of validation output for " + certificate);
        }
    }

    private boolean verifySignature(X509Certificate subjectCertificate, X509Certificate issuerCertificate) {
        try {
            subjectCertificate.verify(issuerCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            logger.debug("Unable to verify certificate for signature", e);
            return false;
        }
    }

    private String convertMillisecondsToTimeString(long milliseconds) {
        final long dy = TimeUnit.MILLISECONDS.toDays(milliseconds);
        final long hr = TimeUnit.MILLISECONDS.toHours(milliseconds)
                - TimeUnit.DAYS.toHours(TimeUnit.MILLISECONDS.toDays(milliseconds));
        final long min = TimeUnit.MILLISECONDS.toMinutes(milliseconds)
                - TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(milliseconds));
        final long sec = TimeUnit.MILLISECONDS.toSeconds(milliseconds)
                - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(milliseconds));

        return "%d days %d hours %d minutes %d seconds".formatted(dy, hr, min, sec);
    }

    private Map<CertificateValidationCheck, CertificateValidationCheckDto> initializeValidationOutput() {
        Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput = new LinkedHashMap<>();
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_CHAIN, new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.SIGNATURE_VERIFICATION, new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_VALIDITY, new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.OCSP_VERIFICATION, new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.CRL_VERIFICATION, new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.BASIC_CONSTRAINTS, new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.KEY_USAGE, new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.NOT_CHECKED, null));
        return validationOutput;
    }

}
