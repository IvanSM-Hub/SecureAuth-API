package com.ivansario.secureauth.service.interfaces;

import java.util.List;

import com.ivansario.secureauth.dto.protect.ObviousPasswordIdRequest;
import com.ivansario.secureauth.entity.ObviousPassword;

public interface ObviousPasswordService {

    ObviousPassword createObviousPassword(ObviousPassword obviousPassword);
    List<ObviousPassword> findAllObviousPasswords();
    ObviousPassword findObviousPasswordById(ObviousPasswordIdRequest request);
    boolean deleteObviousPassword(ObviousPasswordIdRequest request);
    List<ObviousPassword> bulkSave(List<ObviousPassword> obviousPasswords);
    boolean isValidPassword(String password);

}
