package com.czertainly.core.api.web;

import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.core.web.CertificateController;
import com.czertainly.api.model.client.approval.ApprovalResponseDto;
import com.czertainly.api.model.client.certificate.*;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.v2.ClientCertificateRequestDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ApprovalService;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.converter.CertificateFormatConverter;
import com.czertainly.core.util.converter.CertificateFormatEncodingConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;


@RestController
public class CertificateControllerImpl implements CertificateController {

    private CertificateService certificateService;

    private CertificateEventHistoryService certificateEventHistoryService;

    private ClientOperationService clientOperationService;

    private ApprovalService approvalService;

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(CertificateFormat.class, new CertificateFormatConverter());
        webdataBinder.registerCustomEditor(CertificateFormatEncoding.class, new CertificateFormatEncodingConverter());
    }

    @Override
    public CertificateResponseDto listCertificates(SearchRequestDto request) throws ValidationException {
        return certificateService.listCertificates(SecurityFilter.create(), request);
    }

    @Override
    public CertificateDetailDto getCertificate(@PathVariable String uuid)
            throws NotFoundException, CertificateException, IOException {
        return certificateService.getCertificate(SecuredUUID.fromString(uuid));
    }

    @Override
    public CertificateDownloadResponseDto downloadCertificate(String uuid, CertificateFormat certificateFormat, CertificateFormatEncoding encoding) throws CertificateException, NotFoundException, IOException {
        return certificateService.downloadCertificate(uuid, certificateFormat, encoding);
    }

    @Override
    public void deleteCertificate(@PathVariable String uuid) throws NotFoundException {
        certificateService.deleteCertificate(SecuredUUID.fromString(uuid));
    }

    @Override
    public void updateCertificateObjects(String uuid, CertificateUpdateObjectsDto request) throws NotFoundException, CertificateOperationException, AttributeException {
        certificateService.updateCertificateObjects(SecuredUUID.fromString(uuid), request);
    }

    @Override
    public void bulkUpdateCertificateObjects(MultipleCertificateObjectUpdateDto request) throws NotFoundException {
        certificateService.bulkUpdateCertificateObjects(SecurityFilter.create(), request);
    }

    @Override
    public ResponseEntity<UuidDto> upload(@RequestBody UploadCertificateRequestDto request)
            throws AlreadyExistException, CertificateException, NoSuchAlgorithmException, NotFoundException, AttributeException {
        CertificateDetailDto dto = certificateService.upload(request);
        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(dto.getUuid())
                .toUri();
        UuidDto responseDto = new UuidDto();
        responseDto.setUuid(dto.getUuid());
        return ResponseEntity.created(location).body(responseDto);
    }

    @Override
    public BulkOperationResponse bulkDeleteCertificate(@RequestBody RemoveCertificateDto request) throws NotFoundException {
        certificateService.bulkDeleteCertificate(SecurityFilter.create(), request);
        BulkOperationResponse response = new BulkOperationResponse();
        response.setMessage("Initiated bulk delete Certificates. Please refresh after some time");
        response.setStatus(BulkOperationStatus.SUCCESS);
        return response;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return certificateService.getSearchableFieldInformationByGroup();
    }


    @Override
    public List<CertificateEventHistoryDto> getCertificateEventHistory(String uuid) throws NotFoundException {
        return certificateEventHistoryService.getCertificateEventHistory(UUID.fromString(uuid));
    }

    @Override
    public List<LocationDto> listLocations(String certificateUuid) throws NotFoundException {
        return certificateService.listLocations(SecuredUUID.fromString(certificateUuid));
    }

    @Override
    public void checkCompliance(CertificateComplianceCheckDto request) throws NotFoundException {
        certificateService.checkCompliance(request);
    }

    @Override
    public CertificateValidationResultDto getCertificateValidationResult(String uuid) throws NotFoundException, CertificateException {
        return certificateService.getCertificateValidationResult(SecuredUUID.fromString(uuid));
    }

    @Override
    public List<BaseAttribute> getCsrGenerationAttributes() {
        return certificateService.getCsrGenerationAttributes();
    }

    @Override
    public List<CertificateContentDto> getCertificateContent(List<String> uuids) {
        return certificateService.getCertificateContent(uuids);
    }

    @Override
    public CertificateDetailDto submitCertificateRequest(ClientCertificateRequestDto request) throws ValidationException, ConnectorException, CertificateException, NoSuchAlgorithmException, AttributeException, CertificateRequestException {
        return clientOperationService.submitCertificateRequest(request, null, null, null);
    }

    @Override
    public CertificateChainResponseDto getCertificateChain(String uuid, boolean withEndCertificate) throws NotFoundException {
        return certificateService.getCertificateChain(SecuredUUID.fromString(uuid), withEndCertificate);
    }

    @Override
    public CertificateChainDownloadResponseDto downloadCertificateChain(String uuid, CertificateFormat certificateFormat, boolean withEndCertificate, CertificateFormatEncoding encoding) throws NotFoundException, CertificateException {
        return certificateService.downloadCertificateChain(SecuredUUID.fromString(uuid), certificateFormat, withEndCertificate, encoding);
    }

    @Override
    public ApprovalResponseDto listCertificateApprovals(final String uuid, final PaginationRequestDto paginationRequestDto) {
        return approvalService.listApprovalsByObject(SecurityFilter.create(), Resource.CERTIFICATE, UUID.fromString(uuid), paginationRequestDto);
    }

    // SETTERs

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setApprovalService(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }
}