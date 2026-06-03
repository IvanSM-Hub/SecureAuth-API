package com.ivansario.secureauth.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ivansario.secureauth.dto.protect.ObviousPasswordIdRequest;
import com.ivansario.secureauth.entity.ObviousPassword;
import com.ivansario.secureauth.repository.ObviousPasswordRepository;
import com.ivansario.secureauth.service.interfaces.ObviousPasswordService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class ObviousPasswordServiceImpl implements ObviousPasswordService {

    private final ObviousPasswordRepository obviousPasswordRepository;

    @Override
    @Transactional
    public ObviousPassword createObviousPassword(ObviousPassword obviousPassword) {
        return obviousPasswordRepository.save(obviousPassword);
    }

    @Override
    @Transactional
    public boolean deleteObviousPassword(ObviousPasswordIdRequest request) {
        ObviousPassword obviousPassword = findObviousPasswordById(request);
        if (obviousPassword == null) {
            return false;
        }

        UUID id = UUID.fromString(request.getId());
        obviousPasswordRepository.delete(obviousPassword);
        return !obviousPasswordRepository.existsById(id);
    }

    @Override
    public List<ObviousPassword> findAllObviousPasswords() {
        return obviousPasswordRepository.findAll();
    }

    @Override
    public ObviousPassword findObviousPasswordById(ObviousPasswordIdRequest request) {
        UUID id = UUID.fromString(request.getId());
        return obviousPasswordRepository.findById(id).orElse(null);
    }

    @Override
    public List<ObviousPassword> bulkSave(List<ObviousPassword> obviousPasswords) {
        return obviousPasswordRepository.saveAll(obviousPasswords);
    }

    @Override
    public boolean isValidPassword(String password) {
        if (password == null) return false;

        String candidate = password.trim();

        if (obviousPasswordRepository.existsByObviousPass(candidate)) return false;

        List<ObviousPassword> obviousPasswords = findAllObviousPasswords();
        for (ObviousPassword op : obviousPasswords) {
            if (op == null || op.getObviousPass() == null) continue;
            if (op.getObviousPass().equalsIgnoreCase(candidate)) {
                return false;
            }
        }

        return true;
    }

}
