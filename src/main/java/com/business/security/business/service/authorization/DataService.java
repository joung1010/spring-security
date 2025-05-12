package com.business.security.business.service.authorization;

import com.business.security.business.endpoint.authorization.model.AccountVo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <b> DataService </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Slf4j
@Service
public class DataService {


    @PreFilter("filterObject.owner == authentication.name")
    public List<AccountVo> writeList(List<AccountVo> list) {
        return list;
    }

    @PreFilter("filterObject.value.owner == authentication.name")
    public Map<String,AccountVo> writeMap(Map<String,AccountVo> map) {
        return map;
    }

    @PostFilter("filterObject.owner == authentication.name")
    public List<AccountVo> readList() {
        List<AccountVo> immutableList = List.of(
                new AccountVo("user", false),
                new AccountVo("db", false),
                new AccountVo("admin", false)
        );
        // 불변 컬렉션을 가변 컬렉션으로 변환
        return new ArrayList<>(immutableList);
    }

    @PostFilter("filterObject.value.owner == authentication.name")
    public Map<String, AccountVo> readMap() {
        Map<String, AccountVo> immutableMap = Map.of(
                "user", new AccountVo("user", false),
                "db", new AccountVo("db", false),
                "admin", new AccountVo("admin", false)
        );
        // 불변 컬렉션을 가변 컬렉션으로 변환
        return new HashMap<>(immutableMap);
    }
}
