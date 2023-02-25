package com.czertainly.core.util.converter;

import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.search.SearchCondition;
import com.czertainly.api.model.core.search.SearchableFields;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.hibernate.query.sqm.ComparisonOperator;
import org.hibernate.query.sqm.tree.predicate.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.Serializable;

/**
 * Tests for class {@link Sql2PredicateConverter}
 */
@SpringBootTest
public class Sql2PredicateConverterTest extends BaseSpringBootTest {

    @Autowired
    private EntityManager entityManager;

    private CriteriaBuilder criteriaBuilder;

    private CriteriaQuery<Certificate> criteriaQuery;

    private Root<Certificate> root;

    private Root<CryptographicKeyItem> rootCryptoKeyItem;

    private final String TEST_VALUE = "test";
    private final String TEST_DATE_VALUE = "2022-01-01";

    private final String TEST_VERIFICATION_TEXT = "{\"status\":\"%STATUS%\"";

    @BeforeEach
    public void prepare() {
        criteriaBuilder = entityManager.getCriteriaBuilder();
        criteriaQuery = criteriaBuilder.createQuery(Certificate.class);
        root = criteriaQuery.from(Certificate.class);
    }

    @Test
    public void testEqualsPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.EQUALS), criteriaBuilder, root);
        Assertions.assertInstanceOf(SqmComparisonPredicate.class, predicateTest);
        Assertions.assertEquals(ComparisonOperator.EQUAL, ((SqmComparisonPredicate) predicateTest).getSqmOperator());
        Assertions.assertEquals(TEST_VALUE, ((SqmComparisonPredicate) predicateTest).getRightHandExpression().toHqlString());
    }

    @Test
    public void testNotEqualsPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.NOT_EQUALS), criteriaBuilder, root);
        Assertions.assertInstanceOf(SqmComparisonPredicate.class, predicateTest);
        Assertions.assertEquals(ComparisonOperator.NOT_EQUAL, ((SqmComparisonPredicate) predicateTest).getSqmOperator());
        Assertions.assertEquals(TEST_VALUE, ((SqmComparisonPredicate) predicateTest).getRightHandExpression().toHqlString());
    }

    @Test
    public void testContainsPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.CONTAINS), criteriaBuilder, root);
        testLikePredicate(predicateTest, "%" + TEST_VALUE + "%");
    }

    @Test
    public void testNotContainsPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.NOT_CONTAINS), criteriaBuilder, root);
        Assertions.assertInstanceOf(SqmJunctionPredicate.class, predicateTest);

        final SqmJunctionPredicate sqmJunctionPredicate = ((SqmJunctionPredicate) predicateTest);
        for (final SqmPredicate predicate : sqmJunctionPredicate.getPredicates()) {
            Assertions.assertTrue(predicate instanceof SqmLikePredicate || predicate instanceof SqmNullnessPredicate);
            if (predicate instanceof SqmLikePredicate) {
                Assertions.assertTrue(predicate.isNegated());
                Assertions.assertEquals("%" + TEST_VALUE + "%", ((SqmLikePredicate) predicate).getPattern().toHqlString());
            } else if (predicate instanceof SqmNullnessPredicate) {
                Assertions.assertFalse(predicate.isNull().isNegated());
            }
        }
    }

    @Test
    public void testStartWithPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.STARTS_WITH), criteriaBuilder, root);
        testLikePredicate(predicateTest, TEST_VALUE + "%");
    }

    @Test
    public void testEndWithPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.ENDS_WITH), criteriaBuilder, root);
        testLikePredicate(predicateTest, "%" + TEST_VALUE);
    }

    @Test
    public void testEmptyPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.EMPTY), criteriaBuilder, root);
        Assertions.assertInstanceOf(SqmNullnessPredicate.class, predicateTest);
        Assertions.assertFalse(predicateTest.isNull().isNegated());
    }

    @Test
    public void testNotEmptyPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.NOT_EMPTY), criteriaBuilder, root);
        Assertions.assertInstanceOf(SqmNullnessPredicate.class, predicateTest);
        Assertions.assertTrue(predicateTest.isNotNull().isNegated());
    }

    @Test
    public void testGreaterPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.GREATER), criteriaBuilder, root);
        Assertions.assertEquals(ComparisonOperator.GREATER_THAN, ((SqmComparisonPredicate) predicateTest).getSqmOperator());
        Assertions.assertEquals(TEST_DATE_VALUE, ((SqmComparisonPredicate) predicateTest).getRightHandExpression().toHqlString());
    }

    @Test
    public void testLesserPredicate() {
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(prepareDummyFilterRequest(SearchCondition.LESSER), criteriaBuilder, root);
        Assertions.assertEquals(ComparisonOperator.LESS_THAN, ((SqmComparisonPredicate) predicateTest).getSqmOperator());
        Assertions.assertEquals(TEST_DATE_VALUE, ((SqmComparisonPredicate) predicateTest).getRightHandExpression().toHqlString());
    }

    @Test
    public void testOCSPValidation() {
        testVerifications(SearchableFields.OCSP_VALIDATION, SearchCondition.EQUALS, CertificateValidationStatus.SUCCESS);
    }

    @Test
    public void testSignatureValidation() {
        testVerifications(SearchableFields.SIGNATURE_VALIDATION, SearchCondition.NOT_EQUALS, CertificateValidationStatus.FAILED);
    }

    @Test
    public void testCRLValidation() {
        testVerifications(SearchableFields.CRL_VALIDATION, SearchCondition.EQUALS, CertificateValidationStatus.EXPIRED);
    }

    @Test
    public void testReplaceSearchCondition() {
        rootCryptoKeyItem = criteriaQuery.from(CryptographicKeyItem.class);
        final SearchFilterRequestDTODummy searchFilterRequestDtoDummy = prepareDummyFilterRequest(SearchCondition.EQUALS);
        searchFilterRequestDtoDummy.setFieldTest(SearchableFields.CKI_USAGE);
        searchFilterRequestDtoDummy.setValueTest("sign");

        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(searchFilterRequestDtoDummy, criteriaBuilder, rootCryptoKeyItem);
        Assertions.assertInstanceOf(SqmLikePredicate.class, predicateTest);

        final String predicateHqlString = ((SqmLikePredicate) predicateTest).getPattern().toHqlString();
        Assertions.assertTrue(predicateHqlString.startsWith("%"));
        Assertions.assertTrue(predicateHqlString.endsWith("%"));
    }

    private void testLikePredicate(final Predicate predicate, final String value) {
        Assertions.assertInstanceOf(SqmLikePredicate.class, predicate);
        Assertions.assertEquals(value, ((SqmLikePredicate) predicate).getPattern().toHqlString());
    }

    private void testVerifications(final SearchableFields fieldTest, final SearchCondition condition, final CertificateValidationStatus certificateValidationStatus) {
        final SearchFilterRequestDTODummy searchFilterRequestDTODummy
                = new SearchFilterRequestDTODummy(fieldTest, condition, certificateValidationStatus.getCode());
        final Predicate predicateTest = Sql2PredicateConverter.mapSearchFilter2Predicate(searchFilterRequestDTODummy, criteriaBuilder, root);
        Assertions.assertInstanceOf(SqmLikePredicate.class, predicateTest);

        final String hqlString = ((SqmLikePredicate)predicateTest).getPattern().toHqlString();
        Assertions.assertTrue(hqlString.contains(TEST_VERIFICATION_TEXT.replace("%STATUS%", certificateValidationStatus.getCode())));
        Assertions.assertTrue(hqlString.startsWith("%"));
        Assertions.assertTrue(hqlString.endsWith("%"));
    }


    private SearchFilterRequestDTODummy prepareDummyFilterRequest(final SearchCondition condition) {
        SearchFilterRequestDTODummy dummy = null;
        switch (condition) {
            case EQUALS ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.EQUALS, TEST_VALUE);
            case NOT_EQUALS ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.NOT_EQUALS, TEST_VALUE);
            case CONTAINS ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.CONTAINS, TEST_VALUE);
            case NOT_CONTAINS ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.NOT_CONTAINS, TEST_VALUE);
            case STARTS_WITH ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.STARTS_WITH, TEST_VALUE);
            case ENDS_WITH ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.ENDS_WITH, TEST_VALUE);
            case EMPTY ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.EMPTY, TEST_VALUE);
            case NOT_EMPTY ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.COMMON_NAME, SearchCondition.NOT_EMPTY, TEST_VALUE);
            case GREATER ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.NOT_AFTER, SearchCondition.GREATER, TEST_DATE_VALUE);
            case LESSER ->
                    dummy = new SearchFilterRequestDTODummy(SearchableFields.NOT_BEFORE, SearchCondition.LESSER, TEST_DATE_VALUE);
        }
        return dummy;
    }


}

class SearchFilterRequestDTODummy extends SearchFilterRequestDto {

    private SearchableFields fieldTest;
    private SearchCondition conditionTest;
    private Serializable valueTest;

    public SearchFilterRequestDTODummy(SearchableFields fieldTest, SearchCondition conditionTest, Serializable valueTest) {
        this.fieldTest = fieldTest;
        this.conditionTest = conditionTest;
        this.valueTest = valueTest;
    }

    public SearchableFields getField() {
        return fieldTest;
    }

    public SearchCondition getCondition() {
        return conditionTest;
    }

    public Serializable getValue() {
        return valueTest;
    }

    public void setFieldTest(SearchableFields fieldTest) {
        this.fieldTest = fieldTest;
    }

    public void setConditionTest(SearchCondition conditionTest) {
        this.conditionTest = conditionTest;
    }

    public void setValueTest(Serializable valueTest) {
        this.valueTest = valueTest;
    }
}