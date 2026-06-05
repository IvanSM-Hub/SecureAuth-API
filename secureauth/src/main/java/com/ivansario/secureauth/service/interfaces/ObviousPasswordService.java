package com.ivansario.secureauth.service.interfaces;

import java.util.List;

import com.ivansario.secureauth.dto.protect.ObviousPasswordIdRequest;
import com.ivansario.secureauth.entity.ObviousPassword;

/**
 * Service contract for managing obvious/common password records.
 */
public interface ObviousPasswordService {

    /**
     * Creates a new obvious password record.
     *
     * @param obviousPassword entity to persist
     * @return persisted entity
     */
    ObviousPassword createObviousPassword(ObviousPassword obviousPassword);

    /**
     * Returns every stored obvious password entry.
     *
     * @return all obvious password records
     */
    List<ObviousPassword> findAllObviousPasswords();

    /**
     * Finds an obvious password by id.
     *
     * @param request id payload
     * @return found entity or {@code null}
     */
    ObviousPassword findObviousPasswordById(ObviousPasswordIdRequest request);

    /**
     * Deletes an obvious password by id.
     *
     * @param request id payload
     * @return {@code true} when deletion was successful
     */
    boolean deleteObviousPassword(ObviousPasswordIdRequest request);

    /**
     * Persists a list of obvious password records.
     *
     * @param obviousPasswords entities to persist
     * @return saved entities
     */
    List<ObviousPassword> bulkSave(List<ObviousPassword> obviousPasswords);

    /**
     * Validates that a password is not considered obvious.
     *
     * @param password raw password candidate
     * @return {@code true} when the password is acceptable
     */
    boolean isValidPassword(String password);

}
