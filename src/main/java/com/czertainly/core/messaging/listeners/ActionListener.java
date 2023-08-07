package com.czertainly.core.messaging.listeners;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.CertificateOperationException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.MessageHandlingException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.core.dao.entity.Approval;
import com.czertainly.core.dao.entity.ApprovalProfileRelation;
import com.czertainly.core.dao.entity.ApprovalProfileVersion;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.ApprovalProfileRelationRepository;
import com.czertainly.core.dao.repository.ApprovalRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.messaging.configuration.RabbitMQConstants;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.messaging.producers.NotificationProducer;
import com.czertainly.core.service.ApprovalService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.AuthHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;

@Component
@Transactional
public class ActionListener {
    private static final Logger logger = LoggerFactory.getLogger(ActionListener.class);

    private ApprovalProfileRelationRepository approvalProfileRelationRepository;

    private ApprovalService approvalService;

    private ApprovalRepository approvalRepository;

    private ClientOperationService clientOperationService;

    private CertificateRepository certificateRepository;

    private ObjectMapper mapper = new ObjectMapper();

    private NotificationProducer notificationProducer;

    @RabbitListener(queues = RabbitMQConstants.QUEUE_ACTIONS_NAME, messageConverter = "jsonMessageConverter")
    public void processMessage(final ActionMessage actionMessage) throws MessageHandlingException {
        if (actionMessage.getApprovalUuid() == null) {
            final Optional<List<ApprovalProfileRelation>> approvalProfileRelationOptional = approvalProfileRelationRepository.findByResourceUuidAndResource(actionMessage.getRaProfileUuid(), Resource.RA_PROFILE);
            if (approvalProfileRelationOptional.isPresent() && !approvalProfileRelationOptional.get().isEmpty()) {
                try {
                    final ApprovalProfileRelation approvalProfileRelation = approvalProfileRelationOptional.get().get(0);
                    final ApprovalProfileVersion approvalProfileVersion = approvalProfileRelation.getApprovalProfile().getTheLatestApprovalProfileVersion();
                    final Approval approval = approvalService.createApproval(approvalProfileVersion, actionMessage.getResource(), actionMessage.getResourceAction(), actionMessage.getResourceUuid(), actionMessage.getUserUuid(), actionMessage.getData());
                    logger.info("Created new Approval {} for object {}", approval.getUuid(), actionMessage.getResourceUuid());
                }
                catch (Exception e) {
                    logger.error("Cannot create new approval for resource {} and object {}: {}", actionMessage.getResource().getLabel(), actionMessage.getResourceUuid(), e.toString());
                    throw new MessageHandlingException(RabbitMQConstants.QUEUE_ACTIONS_NAME, actionMessage, "Handling of action approval creation failed: " + e.getMessage());
                }
                return;
            }
        }

        try {
            AuthHelper.authenticateAsUser(actionMessage.getUserUuid());
            processTheActivity(actionMessage);
        } catch (Exception e) {
            String errorMessage = String.format("Failed to perform %s %s action!", actionMessage.getResource().getLabel(), actionMessage.getResourceAction().getCode());
            logger.error(errorMessage, e);
            notificationProducer.produceNotificationText(actionMessage.getResource(), actionMessage.getResourceUuid(),
                    NotificationRecipient.buildUserNotificationRecipient(actionMessage.getUserUuid()), errorMessage, e.getMessage());
            throw new MessageHandlingException(RabbitMQConstants.QUEUE_ACTIONS_NAME, actionMessage, "Unable to process action: " + e.getMessage());
        }
    }

    private void processTheActivity(final ActionMessage actionMessage) throws CertificateOperationException, ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException {
        switch (actionMessage.getResource()) {
            case CERTIFICATE -> {
                processCertificateActivity(actionMessage);
            }
            default -> logger.error("There is not allow other resources than CERTIFICATE (for now)");
        }
    }

    private void processCertificateActivity(final ActionMessage actionMessage) throws ConnectorException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, CertificateOperationException {
        Certificate certificate = null;
        if (actionMessage.getResourceUuid() != null) {
            Optional<Certificate> certificateOptional = certificateRepository.findByUuid(actionMessage.getResourceUuid());
            if (certificateOptional.isPresent()) {
                certificate = certificateOptional.get();
            }
        }

        boolean isApproved = actionMessage.getApprovalUuid() != null;
        switch (actionMessage.getResourceAction()) {
            case ISSUE -> {
                clientOperationService.issueCertificateAction(actionMessage.getResourceUuid(), isApproved);
            }
            case REKEY -> {
                final ClientCertificateRekeyRequestDto clientCertificateRekeyRequestDto = mapper.convertValue(actionMessage.getData(), ClientCertificateRekeyRequestDto.class);
                clientOperationService.rekeyCertificateAction(actionMessage.getResourceUuid(), clientCertificateRekeyRequestDto, isApproved);
            }
            case RENEW -> {
                final ClientCertificateRenewRequestDto clientCertificateRenewRequestDto = mapper.convertValue(actionMessage.getData(), ClientCertificateRenewRequestDto.class);
                clientOperationService.renewCertificateAction(actionMessage.getResourceUuid(), clientCertificateRenewRequestDto, isApproved);
            }
            case REVOKE -> {
                final ClientCertificateRevocationDto clientCertificateRevocationDto = mapper.convertValue(actionMessage.getData(), ClientCertificateRevocationDto.class);
                clientOperationService.revokeCertificateAction(actionMessage.getResourceUuid(), clientCertificateRevocationDto, isApproved);
            }
        }
    }

    // SETTERs

    @Autowired
    public void setApprovalProfileRelationRepository(ApprovalProfileRelationRepository approvalProfileRelationRepository) {
        this.approvalProfileRelationRepository = approvalProfileRelationRepository;
    }

    @Autowired
    public void setApprovalService(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    @Autowired
    public void setApprovalRepository(ApprovalRepository approvalRepository) {
        this.approvalRepository = approvalRepository;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }
}