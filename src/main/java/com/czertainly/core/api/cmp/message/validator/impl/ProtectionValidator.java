package com.czertainly.core.api.cmp.message.validator.impl;

import com.czertainly.core.api.cmp.error.CmpException;
import com.czertainly.core.api.cmp.error.ImplFailureInfo;
import com.czertainly.core.api.cmp.message.ConfigurationContext;
import com.czertainly.core.api.cmp.message.PkiMessageDumper;
import com.czertainly.core.api.cmp.message.validator.Validator;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <pre>[1]
 *       PKIMessage ::= SEQUENCE {
 *          header           PKIHeader,
 *          body             PKIBody,
 *          protection   [0] PKIProtection OPTIONAL,
 *          extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
 *                           OPTIONAL
 *      }
 * </pre>
 * <p>[2] The protectionAlg field specifies the algorithm used to protect the
 *    message.  If no protection bits are supplied (note that PKIProtection
 *    is OPTIONAL) then this field MUST be omitted; if protection bits are
 *    supplied, then this field MUST be supplied.</p>
 *
 * <p>When protection is applied, the following structure is used:
 *    <pre>
 *         PKIProtection ::= BIT STRING
 *    </pre>
 *    The input to the calculation of PKIProtection is the DER encoding of
 *    the following data structure:
 *    <pre>
 *         ProtectedPart ::= SEQUENCE {
 *             header    PKIHeader,
 *             body      PKIBody
 *    }</pre>
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall PKI Message</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">PKI message header</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3">PKI message protection</a>
 */
public class ProtectionValidator implements Validator<PKIMessage, Void> {

    private static final Logger LOG = LoggerFactory.getLogger(ProtectionValidator.class.getName());

    private final ConfigurationContext configuration;

    public ProtectionValidator(ConfigurationContext configuration) {
        this.configuration = configuration;
    }
    
    @Override
    public Void validate(PKIMessage message) throws CmpException {
        ASN1BitString protection = message.getProtection();
        ASN1OctetString tid = message.getHeader().getTransactionID();

        if (protection == null) {
            switch (message.getBody().getType()) {
                case PKIBody.TYPE_ERROR:
                case PKIBody.TYPE_CONFIRM:
                case PKIBody.TYPE_REVOCATION_REP:
                    LOG.warn("TID={} | ignore protection for type={}", tid, PkiMessageDumper.msgTypeAsString(message.getBody()));
                    return null;
                default:
                    throw new CmpException(PKIFailureInfo.notAuthorized,
                            ImplFailureInfo.CRYPTOPRO530);
            }
        }

        final AlgorithmIdentifier protectionAlg = message.getHeader().getProtectionAlg();
        if (protectionAlg == null) {
            throw new CmpException(PKIFailureInfo.notAuthorized,
                    ImplFailureInfo.CRYPTOPRO531);
        }
        if (CMPObjectIdentifiers.passwordBasedMac.equals(protectionAlg.getAlgorithm())) {
            new ProtectionMacValidator(configuration).validate(message);
        } else if (PKCSObjectIdentifiers.id_PBMAC1.equals(protectionAlg.getAlgorithm())) {
            new ProtectionPBMac1Validator(configuration).validate(message);
        } else {
            new ProtectionSignatureValidator(configuration).validate(message);
        }
        return null;
    }
}