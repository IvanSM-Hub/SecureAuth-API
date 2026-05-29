package com.ivansario.secureauth.service.interfaces;

import java.util.List;
import java.util.UUID;

import com.ivansario.secureauth.entity.ObviousPassword;

public interface ObviousPasswordService {

    ObviousPassword createObviousPassword(ObviousPassword obviousPassword);
    List<ObviousPassword> findAllObviousPasswords();
    ObviousPassword findObviousPasswordById(UUID id);
    boolean deleteObviousPassword(UUID id);
    List<ObviousPassword> bulkSave(List<ObviousPassword> obviousPasswords);
    boolean isValidPassword(String password);

}
