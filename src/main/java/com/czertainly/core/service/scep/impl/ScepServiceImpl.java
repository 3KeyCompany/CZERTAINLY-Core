package com.czertainly.core.service.scep.impl;

import com.czertainly.api.clients.cryptography.CryptographicOperationsApiClient;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.CertificateUpdateObjectsDto;
import com.czertainly.api.model.common.collection.DigestAlgorithm;
import com.czertainly.api.model.common.collection.RsaSignatureScheme;
import com.czertainly.api.model.connector.cryptography.enums.KeyType;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateStatus;
import com.czertainly.api.model.core.scep.FailInfo;
import com.czertainly.api.model.core.scep.MessageType;
import com.czertainly.api.model.core.scep.PkiStatus;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.model.core.v2.ClientCertificateRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.entity.scep.ScepTransaction;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.dao.repository.scep.ScepTransactionRepository;
import com.czertainly.core.provider.CzertainlyProvider;
import com.czertainly.core.provider.key.CzertainlyPrivateKey;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertValidationService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.CryptographicKeyService;
import com.czertainly.core.service.scep.ScepService;
import com.czertainly.core.service.scep.message.ScepRequest;
import com.czertainly.core.service.scep.message.ScepResponse;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.CsrUtil;
import com.czertainly.core.util.RandomUtil;
import com.microsoft.intune.scepvalidation.IntuneScepServiceClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
@Transactional
public class ScepServiceImpl implements ScepService {

    public static final String SCEP_URL_PREFIX = "/v1/protocol/scep";
    private static final Logger logger = LoggerFactory.getLogger(ScepServiceImpl.class);
    private static final List<String> SCEP_CA_CAPABILITIES = List.of(
            "POSTPKIOperation",
            "SHA-1",
            "SHA-256",
            "SHA-512",
            "DES3",
            "AES",
            "Renewal",
            "SCEPStandard"
    );
    private List<X509Certificate> caCertificateChain = new ArrayList<>();
    private X509Certificate recipient;
    private boolean raProfileBased;
    private RaProfile raProfile;
    private ScepProfile scepProfile;
    private RaProfileRepository raProfileRepository;
    private ScepProfileRepository scepProfileRepository;
    private ScepTransactionRepository scepTransactionRepository;
    private ClientOperationService clientOperationService;
    private CertValidationService certValidationService;
    private CertificateService certificateService;
    private CryptographicKeyService cryptographicKeyService;
    private CryptographicOperationsApiClient cryptographicOperationsApiClient;

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setScepProfileRepository(ScepProfileRepository scepProfileRepository) {
        this.scepProfileRepository = scepProfileRepository;
    }

    @Autowired
    public void setScepTransactionRepository(ScepTransactionRepository scepTransactionRepository) {
        this.scepTransactionRepository = scepTransactionRepository;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertValidationService(CertValidationService certValidationService) {
        this.certValidationService = certValidationService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Autowired
    public void setCryptographicOperationsApiClient(CryptographicOperationsApiClient cryptographicOperationsApiClient) {
        this.cryptographicOperationsApiClient = cryptographicOperationsApiClient;
    }

    public void setRecipient(String certificateContent) {
        try {
            this.recipient = CertificateUtil.parseCertificate(certificateContent);
        } catch (CertificateException e) {
            // This should not occur
            throw new IllegalArgumentException("Error converting the certificate to x509 object");
        }
    }

    @Override
    public ResponseEntity<Object> handleGet(String profileName, String operation, String message) throws ScepException {
        byte[] encoded = new byte[0];
        if (message != null) {
            encoded = message.getBytes();
        }
        return service(profileName, operation, encoded);
    }

    @Override
    public ResponseEntity<Object> handlePost(String profileName, String operation, byte[] message) throws ScepException {
        return service(profileName, operation, message);
    }

    private ResponseEntity<Object> service(String profileName, String operation, byte[] message) throws ScepException {
        init(profileName);
        validateProfile();
        return switch (operation) {
            case "GetCACert" -> caCertificateChain.size() > 1 ? getCaCertChain() : getCaCert();
            case "GetCACaps" -> getCaCaps();
            case "PKIOperation" -> pkiOperation(message);
            default ->
                    buildResponse(null, buildFailedResponse(new ScepException("Unsupported Operation", FailInfo.BAD_REQUEST)));
        };
    }

    private void init(String profileName) {
        this.raProfileBased = ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUriString().contains("/raProfile/");
        if (raProfileBased) {
            raProfile = raProfileRepository.findByName(profileName).orElse(null);
            if (raProfile == null) {
                return;
            }
            scepProfile = raProfile.getScepProfile();
        } else {
            scepProfile = scepProfileRepository.findByName(profileName).orElse(null);
            if (scepProfile == null) {
                return;
            }
            raProfile = scepProfile.getRaProfile();
        }

        Certificate scepCaCertificate = scepProfile.getCaCertificate();
        setRecipient(scepCaCertificate.getCertificateContent().getContent());
        this.caCertificateChain = new ArrayList<>();
        for (Certificate certificate : certValidationService.getCertificateChain(scepCaCertificate)) {
            try {
                this.caCertificateChain.add(CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent()));
            } catch (CertificateException e) {
                // This should not happen
                throw new IllegalArgumentException("Error converting the certificate to x509 object");
            }
        }
    }

    private void validateProfile() throws ScepException {
        validateScepProfile();
        validateRaProfile();
    }

    private void validateScepProfile() throws ScepException {
        if (scepProfile == null) {
            throw new ScepException("Requested SCEP Profile not found", FailInfo.BAD_REQUEST);
        }
        if (!scepProfile.isEnabled()) {
            throw new ScepException("SCEP Profile is not enabled", FailInfo.BAD_REQUEST);
        }
        if (scepProfile.getCaCertificate() == null) {
            throw new ScepException("SCEP Profile does not have any associated CA certificate", FailInfo.BAD_REQUEST);
        }
        if (!raProfileBased && scepProfile.getRaProfile() == null) {
            throw new ScepException("SCEP Profile does not contain associated RA Profile", FailInfo.BAD_REQUEST);
        }
    }

    private void validateRaProfile() throws ScepException {
        if (raProfile == null) {
            throw new ScepException("Requested RA Profile not found", FailInfo.BAD_REQUEST);
        }
        if (!raProfile.getEnabled()) {
            throw new ScepException("RA Profile is not enabled", FailInfo.BAD_REQUEST);
        }
        if (raProfileBased && raProfile.getScepProfile() == null) {
            throw new ScepException("RA Profile does not contain associated SCEP Profile", FailInfo.BAD_REQUEST);
        }
    }

    private ResponseEntity<Object> getCaCert() {
        try {
            byte[] encoded = recipient.getEncoded();
            return getResponseEntity(encoded, "application/x-x509-ca-cert", encoded.length);
        } catch (CertificateException e) {
            // This should not happen
            throw new IllegalArgumentException("Error converting the certificate to x509 object");
        }
    }

    private ResponseEntity<Object> getCaCertChain() throws ScepException {
        byte[] encoded;
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        try {
            generator.addCertificates(new JcaCertStore(caCertificateChain));
            encoded = generator.generate(new CMSProcessableByteArray(new byte[0])).getEncoded();
        } catch (CertificateEncodingException | IOException | CMSException e) {
            return buildResponse(null, buildFailedResponse(new ScepException("Error generating CA certificate chain", e, FailInfo.BAD_REQUEST)));
        }
        return getResponseEntity(encoded, "application/x-x509-ca-ra-cert", encoded.length);
    }

    private ResponseEntity<Object> getCaCaps() {
        return getResponseEntity(String.join(System.lineSeparator(), SCEP_CA_CAPABILITIES), "text/plain", null);
    }

    private ResponseEntity<Object> getResponseEntity(Object body, String contentType, Integer contentLength) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("Content-Type", contentType);
        if (contentLength != null) responseHeaders.set("Content-Length", String.valueOf(contentLength));
        return new ResponseEntity<>(body, responseHeaders, HttpStatus.OK);
    }

    private ResponseEntity<Object> pkiOperation(byte[] body) throws ScepException {
        ScepRequest scepRequest;
        ScepResponse scepResponse;
        IntuneScepServiceClient intuneClient = null;

        scepRequest = new ScepRequest(body);

        // Get the private key from the configuration of SCEP Profile
        CzertainlyPrivateKey czertainlyPrivateKey = cryptographicKeyService.getCzertainlyPrivateKey(scepProfile.getCaCertificate().getKey());

        if (czertainlyPrivateKey == null) {
            return buildResponse(scepRequest, buildFailedResponse(new ScepException("Private key not found in SCEP Profile", FailInfo.BAD_REQUEST)));
        }

        CzertainlyProvider czertainlyProvider = CzertainlyProvider.getInstance(scepProfile.getName(), true, cryptographicOperationsApiClient);

        // decrypt the PKCS#10 request
        try {
            scepRequest.decryptData(
                    czertainlyPrivateKey,
                    czertainlyProvider,
                    cryptographicKeyService.getKeyItemFromKey(scepProfile.getCaCertificate().getKey(), KeyType.PRIVATE_KEY).getCryptographicAlgorithm(),
                    scepProfile.getChallengePassword()
            );
        } catch (CMSException e) {
            return buildResponse(scepRequest, buildFailedResponse(new ScepException("Unable to decrypt the data. " + e.getMessage(), FailInfo.BAD_REQUEST)));
        }

        if (scepProfile.getIntuneTenant() != null) {
            Properties properties = getIntuneConfiguration();
            intuneClient = buildIntuneClient(properties);
        }

        // validate challenge password, if configured
        if (!validateScepChallengePassword(scepRequest.getChallengePassword())) {
            return buildResponse(scepRequest, buildFailedResponse(new ScepException("Challenge password validation failed.", FailInfo.BAD_MESSAGE_CHECK)));
        }

        // validate the request POP
        try {
            verifyRequest(scepRequest);
        } catch (ScepException e) {
            return buildResponse(scepRequest, buildFailedResponse(e));
        }

        if (scepTransactionRepository.existsByTransactionIdAndScepProfile(scepRequest.getTransactionId(), scepProfile)) {
            try {
                scepResponse = getExistingTransaction(scepRequest.getTransactionId());
            } catch (CertificateException e) {
                scepResponse = buildFailedResponse(new ScepException("Error while formatting certificate", FailInfo.BAD_REQUEST));
            }
        } else if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            try {
                // Manual approval for the SCEP clients are configured in the SCEP Profile.
                // If the SCEP Profile has the manual approval set to true, only the CSR will be generated
                if (scepProfile.getRequireManualApproval() != null && !scepProfile.getRequireManualApproval()) {
                    scepResponse = issueCertificate(scepRequest, intuneClient);
                } else {
                    scepResponse = generateCsr(scepRequest, intuneClient);
                }
            } catch (Exception e) {
                scepResponse = buildFailedResponse(new ScepException("Failed to process SCEP request", e, FailInfo.BAD_REQUEST));
                if (scepProfile.getIntuneTenant() != null) {
                    sendIntuneFailureMessage(
                            intuneClient,
                            scepRequest,
                            1L,
                            e.getMessage()
                    );
                }
            }
        } else if (scepRequest.getMessageType().equals(MessageType.CERT_POLL)) {
            scepResponse = pollCertificate(scepRequest, intuneClient);
        } else {
            scepResponse = buildFailedResponse(new ScepException("Unsupported Operation. The requested operation is not supported", FailInfo.BAD_REQUEST));
        }
        return buildResponse(scepRequest, scepResponse);
    }

    private ScepResponse buildFailedResponse(ScepException scepException) {
        ScepResponse scepResponse = new ScepResponse();
        scepResponse.setPkiStatus(PkiStatus.FAILURE);
        scepResponse.setFailInfo(scepException.getFailInfo());
        scepResponse.setFailInfoText(scepException.getMessage());
        logger.error("SCEP error: " + scepException.getMessage());

        return scepResponse;
    }

    private ResponseEntity<Object> buildResponse(ScepRequest scepRequest, ScepResponse scepResponse) throws ScepException {
        prepareMessage(scepRequest, scepResponse);
        CzertainlyProvider czertainlyProvider = CzertainlyProvider.getInstance(scepProfile.getName(), true, cryptographicOperationsApiClient);
        CzertainlyPrivateKey czertainlyPrivateKey = cryptographicKeyService.getCzertainlyPrivateKey(scepProfile.getCaCertificate().getKey());
        try {
            scepResponse.setSigningAttributes(
                    CertificateUtil.getX509Certificate(scepProfile.getCaCertificate().getCertificateContent().getContent()),
                    czertainlyPrivateKey,
                    czertainlyProvider

            );
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        scepResponse.generate();
        byte[] responseBody;
        try {
            responseBody = scepResponse.getSignedResponseData().getEncoded();
        } catch (IOException e) {
            throw new ScepException("Error generating SCEP response", e, FailInfo.BAD_REQUEST);
        }
        return getResponseEntity(responseBody, "application/x-pki-message", responseBody.length);
    }

    private ScepResponse issueCertificate(ScepRequest scepRequest, IntuneScepServiceClient intuneClient) throws Exception {
        if (scepProfile.getIntuneTenant() != null) {
            validateIntuneRequest(
                    intuneClient,
                    scepRequest
            );
        }
        ClientCertificateSignRequestDto requestDto = new ClientCertificateSignRequestDto();
        ScepResponse scepResponse = new ScepResponse();

        requestDto.setPkcs10(new String(Base64.getEncoder().encode(scepRequest.getPkcs10Request().getEncoded())));
        ClientCertificateDataResponseDto response = clientOperationService.issueCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(), raProfile.getSecuredUuid(), requestDto);
        scepResponse.setCertificate(CertificateUtil.parseCertificate(response.getCertificateData()));
        addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());
        scepResponse.setPkiStatus(PkiStatus.SUCCESS);
        sendIntuneSuccessNotification(
                intuneClient,
                scepRequest,
                scepResponse.getIssuedCertificate()
        );
        return scepResponse;
    }


    private ScepResponse generateCsr(ScepRequest scepRequest, IntuneScepServiceClient intuneClient) throws Exception {
        if (scepProfile.getIntuneTenant() != null) {
            validateIntuneRequest(
                    intuneClient,
                    scepRequest
            );
        }
        ClientCertificateRequestDto requestDto = new ClientCertificateRequestDto();
        ScepResponse scepResponse = new ScepResponse();
        requestDto.setPkcs10(new String(Base64.getEncoder().encode(scepRequest.getPkcs10Request().getEncoded())));
        CertificateDetailDto response = clientOperationService.createCsr(requestDto);
        scepResponse.setIssuedCertificate(certificateService.getCertificateEntity(SecuredUUID.fromString(response.getUuid())));
        CertificateUpdateObjectsDto updateObjectsRequest = new CertificateUpdateObjectsDto();
        updateObjectsRequest.setRaProfileUuid(raProfile.getUuid().toString());
        certificateService.updateCertificateObjects(SecuredUUID.fromString(response.getUuid()), updateObjectsRequest);
        addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());
        scepResponse.setPkiStatus(PkiStatus.PENDING);

        return scepResponse;
    }

    private ScepResponse getExistingTransaction(String transactionId) throws CertificateException {
        ScepTransaction scepTransaction = scepTransactionRepository.findByTransactionIdAndScepProfile(transactionId, scepProfile).orElse(null);
        assert scepTransaction != null;
        Certificate certificate = scepTransaction.getCertificate();
        ScepResponse scepResponse = new ScepResponse();
        if (certificate.getStatus() != CertificateStatus.NEW) {
            scepResponse.setPkiStatus(PkiStatus.SUCCESS);
            scepResponse.setCertificate(CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent()));
            scepResponse.setIssuedCertificate(certificate);
        } else {
            scepResponse.setPkiStatus(PkiStatus.PENDING);
        }
        return scepResponse;
    }

    private void addTransactionEntity(String transactionId, String certificateUuid) {
        ScepTransaction scepTransaction = new ScepTransaction();
        scepTransaction.setTransactionId(transactionId);
        scepTransaction.setCertificateUuid(UUID.fromString(certificateUuid));
        scepTransaction.setScepProfile(scepProfile);
        scepTransactionRepository.save(scepTransaction);
    }

    private ScepResponse pollCertificate(ScepRequest scepRequest, IntuneScepServiceClient intuneClient) {
        ScepResponse scepResponse = new ScepResponse();
        try {
            ScepTransaction transaction = getTransaction(scepRequest.getTransactionId());
            if (!transaction.getCertificate().getStatus().equals(CertificateStatus.NEW)) {
                scepResponse.setCertificate(CertificateUtil.parseCertificate(transaction.getCertificate().getCertificateContent().getContent()));
                scepResponse.setPkiStatus(PkiStatus.SUCCESS);
                scepResponse.setIssuedCertificate(transaction.getCertificate());
                sendIntuneSuccessNotification(
                        intuneClient,
                        scepRequest,
                        scepResponse.getIssuedCertificate()
                );
            } else {
                scepResponse.setPkiStatus(PkiStatus.PENDING);
            }
            prepareMessage(scepRequest, scepResponse);

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return scepResponse;
    }

    private void prepareMessage(ScepRequest scepRequest, ScepResponse scepResponse) {
        if (scepRequest == null) {
            return;
        }
        // As per the scep RFC the fields are not to be null. EVen if they are null, these
        // are handled when generating the attributes for the CMS signed data for the response
        scepResponse.setRecipientNonce(scepRequest.getSenderNonce());
        scepResponse.setTransactionId(scepRequest.getTransactionId());
        scepResponse.setCaCertificate(recipient);
        scepResponse.setRecipientKeyInfo(scepRequest.getRequestKeyInfo());
        scepResponse.setDigestAlgorithmOid(scepRequest.getDigestAlgorithmOid());
        scepResponse.setSenderNonce(RandomUtil.generateRandomNonceBase64(16));
        scepResponse.setContentEncryptionAlgorithm(scepRequest.getContentEncryptionAlgorithm());
    }

    private ScepTransaction getTransaction(String transactionId) {
        return scepTransactionRepository.findByTransactionId(transactionId).orElse(null);
    }

    private boolean validateScepChallengePassword(String challengePassword) {
        if (scepProfile.getChallengePassword() == null || scepProfile.getChallengePassword().isEmpty()) {
            return true;
        }
        return challengePassword.equals(scepProfile.getChallengePassword());
    }

    public void verifyRequest(ScepRequest scepRequest) throws ScepException {

        // Throw exception if the request type is not renewal or issuing a new certificate
        if (!scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ) && !scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            throw new ScepException("Unsupported Operation", FailInfo.BAD_REQUEST);
        }

        if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            // Renewal check must be done for PKCS Request also. According to the RFC Version 3.1.1.2
            // (https://datatracker.ietf.org/doc/id/draft-nourse-scep-23.txt), RENEWAL_REQ is not part of the message type
            // Commonly used SCEP clients like JSCEP and SSCEP uses this version of RFC and
            // may use PKCS_REQ for renewal
            renewalValidation(scepRequest);
            try {
                scepRequest.verifyRequest();
            } catch (PKCSException | NoSuchAlgorithmException | InvalidKeyException | OperatorCreationException e) {
                throw new ScepException("Failed to verify PKCS#10 request POP", FailInfo.BAD_REQUEST);
            }
        } else if (scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ)) {
            renewalValidation(scepRequest);
        }
    }

    private void renewalValidation(ScepRequest scepRequest) throws ScepException {
        JcaPKCS10CertificationRequest pkcs10Request = scepRequest.getPkcs10Request();
        Certificate extCertificate = null;
        try {
            extCertificate = certificateService.getCertificateEntityByFingerprint(CertificateUtil.getThumbprint(scepRequest.getSignerCertificate()));
        } catch (NotFoundException e) {
            // Certificate is not found with the fingerprint. Meaning its not a renewal request. So do nothing
            return;
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new ScepException("Unable to parse the signer certificate");
        }
        if (!(new X500Name(extCertificate.getSubjectDn())).equals(pkcs10Request.getSubject())) {
            throw new ScepException("Subject DN for the renewal request does not match the original certificate");
        }
        try {
            if (!scepRequest.verifySignature(scepRequest.getSignerCertificate().getPublicKey())) {
                throw new ScepException("SCEP Request signature verification failed");
            }
        } catch (OperatorCreationException | CMSException e) {
            throw new ScepException("Exception when verifying signature." + e.getMessage());
        }
        // No need to verify the same key pair used in request since it is already handled by the rekey method in client operations
        checkRenewalTimeframe(extCertificate);
    }

    private void checkRenewalTimeframe(Certificate certificate) throws ScepException {
        // Empty renewal threshold or the value 0 will be considered as null value and the half life of the certificate will be assumed
        if (scepProfile.getRenewalThreshold() == null || scepProfile.getRenewalThreshold() == 0) {
            // If the renewal timeframe is not given, we consider that renewal is possible only after the certificate
            // crosses its half lime time
            if (certificate.getValidity() / 2 < certificate.getExpiryInDays()) {
                throw new ScepException("Cannot renew certificate. Validity exceeds the half life time of certificate", FailInfo.BAD_REQUEST);
            }
        } else if (certificate.getStatus().equals(CertificateStatus.EXPIRED) || certificate.getStatus().equals(CertificateStatus.REVOKED)) {
            throw new ScepException("Cannot renew certificate. Certificate is already in expired or revoked state", FailInfo.BAD_REQUEST);
        } else {
            if (certificate.getExpiryInDays() > scepProfile.getRenewalThreshold()) {
                throw new ScepException("Cannot renew certificate. Validity exceeds the configured value in SCEP profile", FailInfo.BAD_REQUEST);
            }
        }
    }

    private Properties getIntuneConfiguration() {
        // Create the properties based on the scep profile Intune properties
        Properties configProperties = new Properties();
        configProperties.put("AAD_APP_ID", scepProfile.getIntuneApplicationId());
        configProperties.put("AAD_APP_KEY", scepProfile.getIntuneApplicationKey());
        configProperties.put("TENANT", scepProfile.getIntuneTenant());
        configProperties.put("PROVIDER_NAME_AND_VERSION", "CZERTAINLY-V2.7.2");
        return configProperties;
    }

    private IntuneScepServiceClient buildIntuneClient(Properties configProperties) {
        return new IntuneScepServiceClient(configProperties);
    }

    private void validateIntuneRequest(IntuneScepServiceClient client, ScepRequest scepRequest) throws Exception {
        if (scepRequest.getTransactionId() == null || scepRequest.getTransactionId().isEmpty()) {
            throw new ScepException("Transaction ID cannot be empty for Intune requests");
        }
        if (scepRequest.getPkcs10Request() == null) {
            throw new ScepException("Cannot initiate Intune validation. PKCS#10 request is empty");
        }
        client.ValidateRequest(
                scepRequest.getTransactionId(),
                CsrUtil.byteArrayCsrToString(scepRequest.getPkcs10Request().getEncoded())
        );
    }

    private void sendIntuneSuccessNotification(
            IntuneScepServiceClient client,
            ScepRequest request,
            Certificate certificate) {
        String pattern = "YYYY-MM-DDThh:mm:ss.sssTZD";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        String expiryDate = simpleDateFormat.format(certificate.getNotAfter());
        String serialNumber = certificate.getSerialNumber();
        String issuingAuthority = certificate.getIssuerCommonName();

        try {
            String sha1Thumbprint = CertificateUtil.getSha1Thumbprint(CertificateUtil.getX509Certificate(certificate.getCertificateContent().getContent()).getEncoded());
            client.SendSuccessNotification(
                    request.getTransactionId(),
                    CsrUtil.byteArrayCsrToString(request.getPkcs10Request().getEncoded()),
                    sha1Thumbprint,
                    serialNumber,
                    expiryDate,
                    issuingAuthority,
                    "",
                    ""
            );
        } catch (Exception e) {
            logger.error("Unable to update Intune with success notification. " + e.getMessage());
        }
    }

    private void sendIntuneFailureMessage(IntuneScepServiceClient client, ScepRequest request, long errorCode, String error) {
        try {
            client.SendFailureNotification(
                    request.getTransactionId(),
                    CsrUtil.byteArrayCsrToString(request.getPkcs10Request().getEncoded()),
                    errorCode,
                    error
            );
        } catch (Exception e) {
            logger.error("Unable to update Intune with failed notification. " + e.getMessage());
        }
    }
}
