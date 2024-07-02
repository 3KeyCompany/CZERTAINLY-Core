package com.czertainly.core.dao.repository;

import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import jakarta.persistence.criteria.*;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;

@NoRepositoryBean
public interface SecurityFilterRepository<T, ID> extends JpaRepository<T, ID> {

    Optional<T> findByUuid(SecuredUUID uuid);

    Optional<T> findByUuid(SecuredUUID uuid, BiFunction<Root<T>, CriteriaBuilder, Predicate> additionalWhereClause);

    List<T> findUsingSecurityFilter(SecurityFilter filter);

    List<T> findUsingSecurityFilter(SecurityFilter filter, boolean enabled);

    List<T> findUsingSecurityFilter(SecurityFilter filter, List<String> fetchAssociations, BiFunction<Root<T>, CriteriaBuilder, Predicate> additionalWhereClause);

    List<T> findUsingSecurityFilter(SecurityFilter filter, List<String> fetchAssociations, BiFunction<Root<T>, CriteriaBuilder, Predicate> additionalWhereClause, Pageable p, BiFunction<Root<T>, CriteriaBuilder, Order> order);

    Long countUsingSecurityFilter(SecurityFilter filter);

    Long countUsingSecurityFilter(SecurityFilter filter, BiFunction<Root<T>, CriteriaBuilder, Predicate> additionalWhereClause);

    List<T> findUsingSecurityFilterByCustomCriteriaQuery(SecurityFilter filter, Root<T> root, CriteriaQuery<T> criteriaQuery, Predicate customPredicates);
}
